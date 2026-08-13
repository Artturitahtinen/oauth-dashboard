using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

public class PkceTests
{
    /// <summary>
    /// The RFC 7636 Appendix B worked example. This is the test that actually matters: an S256
    /// implementation that hashes the wrong thing (the decoded random bytes instead of the ASCII of
    /// the verifier string) or encodes with standard base64 instead of base64url still produces a
    /// plausible 43-character challenge, and the mistake would only surface as an opaque
    /// <c>invalid_grant</c> from the provider at exchange time. Pinning the published vector catches
    /// it here instead.
    /// </summary>
    [Fact]
    public void CodeChallengeFor_MatchesRfc7636AppendixBVector()
    {
        const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string ExpectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        Assert.Equal(ExpectedChallenge, Pkce.CodeChallengeFor(Verifier));
    }

    [Fact]
    public void NewCodeVerifier_MeetsRfc7636LengthBounds()
    {
        var verifier = Pkce.NewCodeVerifier();

        Assert.InRange(verifier.Length, 43, 128);
    }

    /// <summary>
    /// Base64url only, no padding — a raw base64 verifier containing '+', '/' or '=' would be
    /// mangled or misread in a query string ('+' decodes as a space).
    /// </summary>
    [Fact]
    public void NewCodeVerifier_UsesOnlyUnreservedCharacters()
    {
        var verifier = Pkce.NewCodeVerifier();

        Assert.True(
            verifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'),
            $"Verifier contained a character outside the RFC 7636 unreserved set: {verifier}");
    }

    /// <summary>
    /// A verifier reused across authorization attempts would defeat the point — an attacker who
    /// captured one exchange could redeem a later stolen code.
    /// </summary>
    [Fact]
    public void NewCodeVerifier_IsUniquePerCall()
    {
        var verifiers = Enumerable.Range(0, 100).Select(_ => Pkce.NewCodeVerifier()).ToList();

        Assert.Equal(verifiers.Count, verifiers.Distinct().Count());
    }

    [Fact]
    public void CodeChallengeFor_IsDeterministic()
    {
        var verifier = Pkce.NewCodeVerifier();

        Assert.Equal(Pkce.CodeChallengeFor(verifier), Pkce.CodeChallengeFor(verifier));
    }

    /// <summary>
    /// The challenge must not be the verifier (that would be the <c>plain</c> method, which leaks
    /// the verifier to anyone who can read the authorize URL).
    /// </summary>
    [Fact]
    public void CodeChallengeFor_DoesNotEchoTheVerifier()
    {
        var verifier = Pkce.NewCodeVerifier();

        Assert.NotEqual(verifier, Pkce.CodeChallengeFor(verifier));
    }
}
