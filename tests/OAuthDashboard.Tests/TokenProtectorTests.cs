using Microsoft.AspNetCore.DataProtection;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Tests;

public class TokenProtectorTests
{
    private const string Token = "gho_a-provider-access-token";

    private static TokenProtector NewProtector(IDataProtectionProvider? provider = null) =>
        new(provider ?? new EphemeralDataProtectionProvider());

    [Fact]
    public void Unprotect_RecoversTheOriginalToken()
    {
        var protector = NewProtector();

        Assert.Equal(Token, protector.Unprotect(protector.Protect(Token)));
    }

    [Fact]
    public void Protect_DoesNotLeaveThePlaintextInTheCiphertext()
    {
        var ciphertext = NewProtector().Protect(Token);

        Assert.DoesNotContain(Token, ciphertext, StringComparison.Ordinal);
    }

    /// <summary>
    /// Data Protection is authenticated encryption, so a tampered ciphertext fails loudly rather
    /// than decrypting to garbage that would then be sent to GitHub as a bearer token.
    /// </summary>
    [Fact]
    public void Unprotect_ThrowsOnTamperedCiphertext()
    {
        var protector = NewProtector();
        var ciphertext = protector.Protect(Token);

        // Flip a character in the middle of the payload.
        var chars = ciphertext.ToCharArray();
        chars[chars.Length / 2] = chars[chars.Length / 2] == 'A' ? 'B' : 'A';

        Assert.ThrowsAny<Exception>(() => protector.Unprotect(new string(chars)));
    }

    /// <summary>
    /// The reason the purpose string matters: ciphertext produced under a different keyring cannot be
    /// read here. This is what keeps the token protector and the auth cookie's protector from being
    /// interchangeable — a cookie value must not be feedable to the token unprotector.
    /// </summary>
    [Fact]
    public void Unprotect_CannotReadCiphertextFromAnotherKeyring()
    {
        var ciphertext = NewProtector().Protect(Token);
        var otherProtector = NewProtector();

        Assert.ThrowsAny<Exception>(() => otherProtector.Unprotect(ciphertext));
    }

    [Fact]
    public void ProtectOptional_PassesNullThroughUntouched()
    {
        var protector = NewProtector();

        Assert.Null(protector.ProtectOptional(null));
        Assert.Null(protector.UnprotectOptional(null));
        Assert.Equal(Token, protector.UnprotectOptional(protector.ProtectOptional(Token)));
    }
}
