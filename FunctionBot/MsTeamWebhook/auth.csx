using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Encapsulates auth results.
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthResponse"/> class.
    /// </summary>
    /// <param name="authSuccessful">if set to <c>true</c> then [authentication was successful].</param>
    /// <param name="errorMessage">The error message.</param>
    public AuthResponse(bool authSuccessful, string errorMessage)
    {
        this.AuthSuccessful = authSuccessful;
        this.ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Gets a value indicating whether [authentication successful].
    /// </summary>
    /// <value>
    /// <c>true</c> if [authentication successful]; otherwise, <c>false</c>.
    /// </value>
    public bool AuthSuccessful { get; private set; }

    /// <summary>
    /// Gets the error message.
    /// </summary>
    /// <value>
    /// The error message.
    /// </value>
    public string ErrorMessage { get; private set; }
}

/// <summary>
/// Provides authentication results.
/// </summary>
public class AuthProvider
{
    /// <summary>
    /// A dictionary for storing signing keys. Here, the look up key is based on the value of the query parameter 'id'.
    /// The signing keys must be valid 256 bit base64 encoded strings that are provided during custom bot registration in MS Teams client.
    /// </summary>
    private static readonly Dictionary<string, string> SigningKeyDictionary = new Dictionary<string, string>()
            {
                {"delegate", "7nd9levhMhndzf8J/oo51n2JiS7s7NajTkI+oH2vzqg=" },
                {"fabrikam", "QgyNSToQjf4p6+YzDpjKks1/tXeJQ7FhVHqRwTnugVI=" }
            };

    /// <summary>
    /// Validates the specified authentication header value.
    /// </summary>
    /// <param name="httpRequestMessage">The HTTP request message.</param>
    /// <returns>
    /// Response containing result of validation.
    /// </returns>
    public static async Task<AuthResponse> Validate(HttpRequestMessage httpRequestMessage)
    {
        string messageContent = await httpRequestMessage.Content.ReadAsStringAsync();
        AuthenticationHeaderValue authenticationHeaderValue = httpRequestMessage.Headers.Authorization;

        // It is up to the custom bot owner to decide how to pass in the lookup id for the signing key.
        // Here, we have used the query parameter "id" as an example.

        string claimedSenderId = httpRequestMessage.GetQueryNameValuePairs().FirstOrDefault(q => string.Compare(q.Key, "id", true) == 0).Value;

        if (string.IsNullOrEmpty(claimedSenderId))
        {
            return new AuthResponse(false, "Id not present on request.");
        }

        if (authenticationHeaderValue == null)
        {
            return new AuthResponse(false, "Authentication header not present on request.");
        }

        if (!string.Equals("HMAC", authenticationHeaderValue.Scheme))
        {
            return new AuthResponse(false, "Incorrect authorization header scheme.");
        }

        claimedSenderId = claimedSenderId.ToLower();
        string signingKey = null;
        if (!AuthProvider.SigningKeyDictionary.TryGetValue(claimedSenderId, out signingKey))
        {
            return new AuthResponse(false, string.Format("Signing key for {0} is not configured", claimedSenderId));
        }

        // Reject all empty messages
        if (string.IsNullOrEmpty(messageContent))
        {
            return new AuthResponse(false, "Unable to validate authentication header for messages with empty body.");
        }

        string providedHmacValue = authenticationHeaderValue.Parameter;
        string calculatedHmacValue = null;
        try
        {
            byte[] serializedPayloadBytes = Encoding.UTF8.GetBytes(messageContent);

            byte[] keyBytes = Convert.FromBase64String(signingKey);
            using (HMACSHA256 hmacSHA256 = new HMACSHA256(keyBytes))
            {
                byte[] hashBytes = hmacSHA256.ComputeHash(serializedPayloadBytes);
                calculatedHmacValue = Convert.ToBase64String(hashBytes);
            }

            if (string.Equals(providedHmacValue, calculatedHmacValue))
            {
                return new AuthResponse(true, null);
            }
            else
            {
                string errorMessage = string.Format(
                    "AuthHeaderValueMismatch. Expected:'{0}' Provided:'{1}'",
                    calculatedHmacValue,
                    providedHmacValue);
                return new AuthResponse(false, errorMessage);
            }
        }
        catch (Exception ex)
        {
            Trace.TraceError("Exception occcured while verifying HMAC on the incoming request. Exception: {0}", ex);
            return new AuthResponse(false, "Exception thrown while verifying MAC on incoming request.");
        }
    }
}