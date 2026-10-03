using System.Security.Cryptography;
using System.Text;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// PKCE (RFC 7636) code verifier/challenge generation, S256 method.
/// </summary>
/// <remarks>
/// PKCE closes the gap between the authorization code arriving in a browser redirect and the code
/// being exchanged server-to-server. The challenge goes out with <c>/authorize</c> over a URL that
/// is visible to the browser, logs, and history; the verifier never leaves this process until it is
/// POSTed directly to the token endpoint. Stealing the code therefore isn't enough — the thief
/// would also need the verifier, and only the SHA-256 of it was ever exposed.
/// <para>
/// This backend is a <em>confidential</em> client: it holds a client_secret, so an intercepted code
/// is already unusable without it and PKCE is not strictly required. It's implemented anyway
/// because it costs almost nothing, because the OAuth 2.1 draft makes it mandatory for all clients
/// including confidential ones, and because "we have a secret" stops being true the moment any part
/// of this ever runs somewhere a secret can't be kept.
/// </para>
/// <para>
/// <c>plain</c> is the other method the RFC allows and is pointless here — it sends the verifier
/// itself as the challenge, so anyone who can read the authorize URL gets both halves.
/// </para>
/// </remarks>
public static class Pkce
{
    /// <summary>
    /// A fresh high-entropy verifier. 32 random bytes base64url-encode to 43 characters, which is
    /// the minimum length RFC 7636 §4.1 permits (the maximum is 128).
    /// </summary>
    public static string NewCodeVerifier() => Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// The S256 challenge: <c>BASE64URL(SHA256(ASCII(verifier)))</c>. Hashing the ASCII characters
    /// of the verifier string, not the random bytes it was decoded from — a detail worth being
    /// precise about, since hashing the wrong one still produces a plausible-looking 43-character
    /// challenge and fails only at the token exchange.
    /// </summary>
    public static string CodeChallengeFor(string codeVerifier) =>
        Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

    /// <summary>
    /// Base64url without padding, per RFC 7636 Appendix A. Plain base64 would be wrong in a query
    /// string: <c>+</c> decodes as a space and <c>=</c> padding needs escaping.
    /// </summary>
    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
