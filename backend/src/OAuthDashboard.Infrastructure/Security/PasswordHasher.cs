using System.Security.Cryptography;
using System.Text;

namespace OAuthDashboard.Infrastructure.Security;

/// <summary>
/// PBKDF2-HMAC-SHA256 password hashing, in-box via <see cref="Rfc2898DeriveBytes"/>.
/// </summary>
/// <remarks>
/// Three properties matter here, and all three are easy to get wrong by hand — which is exactly why
/// they're written out rather than delegated to Identity:
/// <list type="bullet">
/// <item>A password is <em>hashed</em>, never encrypted. There is deliberately no way back to the
/// plaintext, unlike the provider tokens in <see cref="TokenProtector"/>, which have to be
/// recoverable because they get replayed to GitHub and Google.</item>
/// <item>The salt is per-user and random, so two users choosing the same password get different
/// hashes and one precomputed table can't cover both.</item>
/// <item>Verification is constant-time. A naive <c>==</c> on the hash bytes leaks how many leading
/// bytes matched through its timing, which is enough to reconstruct a hash byte by byte.</item>
/// </list>
/// The stored format is self-describing so the work factor can be raised later without invalidating
/// existing hashes: <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 hash&gt;</c>.
/// </remarks>
public static class PasswordHasher
{
    private const string Prefix = "pbkdf2-sha256";

    // OWASP's current floor for PBKDF2-HMAC-SHA256. Deliberately slow: the entire defence of a
    // stolen hash is that guessing costs the attacker this much work per attempt.
    private const int Iterations = 600_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);

        return string.Join('$', Prefix, Iterations, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    /// <summary>
    /// Verifies a candidate password against a stored hash. Returns false rather than throwing on a
    /// malformed hash — a corrupt row is a failed login, not a 500 that tells the caller the row exists.
    /// </summary>
    public static bool Verify(string password, string storedHash)
    {
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix || !int.TryParse(parts[1], out var iterations))
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = Derive(password, salt, iterations, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int outputBytes = HashBytes) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            outputBytes);
}
