using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Tests;

public class PasswordHasherTests
{
    private const string Password = "correct-horse-battery-staple";

    [Fact]
    public void Verify_AcceptsTheOriginalPassword()
    {
        Assert.True(PasswordHasher.Verify(Password, PasswordHasher.Hash(Password)));
    }

    [Theory]
    [InlineData("Correct-horse-battery-staple")] // case matters
    [InlineData("correct-horse-battery-stapl")]  // one character short
    [InlineData("")]
    public void Verify_RejectsAnythingElse(string attempt)
    {
        Assert.False(PasswordHasher.Verify(attempt, PasswordHasher.Hash(Password)));
    }

    /// <summary>
    /// Per-user random salt: the same password hashed twice must not collide, or one precomputed
    /// table would cover every user who picked it.
    /// </summary>
    [Fact]
    public void Hash_ProducesADifferentHashEachTimeForTheSamePassword()
    {
        Assert.NotEqual(PasswordHasher.Hash(Password), PasswordHasher.Hash(Password));
    }

    /// <summary>
    /// The stored value must never contain the password itself — the point of hashing is that the
    /// plaintext is unrecoverable, unlike the reversibly-encrypted provider tokens.
    /// </summary>
    [Fact]
    public void Hash_DoesNotContainThePlaintext()
    {
        Assert.DoesNotContain(Password, PasswordHasher.Hash(Password), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The format carries its own algorithm and iteration count so the work factor can be raised
    /// later without invalidating hashes already in the database.
    /// </summary>
    [Fact]
    public void Hash_IsSelfDescribing()
    {
        var parts = PasswordHasher.Hash(Password).Split('$');

        Assert.Equal(4, parts.Length);
        Assert.Equal("pbkdf2-sha256", parts[0]);
        Assert.True(int.TryParse(parts[1], out var iterations));
        Assert.True(iterations >= 600_000, $"Work factor dropped below the OWASP floor: {iterations}");
    }

    /// <summary>
    /// A hash stored with a lower iteration count still verifies, which is what makes raising the
    /// work factor a non-breaking change.
    /// </summary>
    [Fact]
    public void Verify_HonoursTheIterationCountStoredInTheHash()
    {
        // Built by hand at a deliberately low work factor, mimicking an older stored hash.
        var salt = Convert.ToBase64String(new byte[16]);
        var legacy = $"pbkdf2-sha256$1000${salt}${Convert.ToBase64String(
            System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
                System.Text.Encoding.UTF8.GetBytes(Password),
                new byte[16],
                1000,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                32))}";

        Assert.True(PasswordHasher.Verify(Password, legacy));
    }

    /// <summary>
    /// A corrupt or truncated row is a failed login, not an exception — a 500 here would confirm to
    /// the caller that the account exists.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2-sha256$notanumber$AAAA$AAAA")]
    [InlineData("pbkdf2-sha256$600000$!!!not-base64!!!$AAAA")]
    [InlineData("bcrypt$600000$AAAA$AAAA")]
    public void Verify_ReturnsFalseOnMalformedHashesInsteadOfThrowing(string storedHash)
    {
        Assert.False(PasswordHasher.Verify(Password, storedHash));
    }
}
