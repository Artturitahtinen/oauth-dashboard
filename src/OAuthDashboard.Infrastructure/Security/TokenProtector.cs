using Microsoft.AspNetCore.DataProtection;

namespace OAuthDashboard.Infrastructure.Security;

/// <summary>
/// Encrypts provider access/refresh tokens before they touch SQLite, using Data Protection.
/// </summary>
/// <remarks>
/// Unlike a password (see <see cref="PasswordHasher"/>), these have to be <em>recoverable</em> —
/// the whole point is to replay them to GitHub and Google later — so this is real reversible
/// encryption, not hashing.
/// <para>
/// The purpose string is the important detail. Data Protection derives a distinct key per purpose,
/// so ciphertext produced here cannot be decrypted by a protector created for any other purpose
/// (the auth cookie's, for instance). If tokens and cookies shared a purpose, a cookie value could
/// be fed to the token unprotector and vice versa.
/// </para>
/// <para>
/// What this does and does not buy: at rest the SQLite file alone is useless, so a copied
/// <c>oauthdashboard.db</c> leaks nothing. But in development the keyring sits unencrypted next to
/// it under <c>%LOCALAPPDATA%\ASP.NET\DataProtection-Keys</c>, so an attacker with the whole
/// machine has both halves. This defends against a leaked database file, not against a compromised
/// host — a real deployment would put the keyring in a KMS or behind a certificate.
/// </para>
/// </remarks>
public class TokenProtector
{
    private const string Purpose = "OAuthDashboard.ProviderTokens.v1";

    private readonly IDataProtector _protector;

    public TokenProtector(IDataProtectionProvider provider) =>
        _protector = provider.CreateProtector(Purpose);

    public string Protect(string token) => _protector.Protect(token);

    public string Unprotect(string ciphertext) => _protector.Unprotect(ciphertext);

    /// <summary>Convenience for the nullable refresh-token column: null in, null out.</summary>
    public string? ProtectOptional(string? token) => token is null ? null : Protect(token);

    public string? UnprotectOptional(string? ciphertext) => ciphertext is null ? null : Unprotect(ciphertext);
}
