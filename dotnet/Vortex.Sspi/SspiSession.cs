using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Vortex.Sspi;

/// <summary>
/// Managed wrapper for the Rust NtlmProvider FFI.
/// </summary>
public unsafe class SspiSession : IDisposable
{
    private NtlmProvider* _handle;
    private bool _disposed;

    public SspiSession()
    {
        _handle = NativeMethods.ntlm_server_create();
        if (_handle == null)
        {
            throw new Exception("Failed to allocate NTLM provider in Rust.");
        }
    }

    /// <summary>
    /// Processes an NTLM token. Returns the challenge token if ContinueNeeded, or null if Complete.
    /// </summary>
    public byte[]? ParseToken(byte[] inputToken, out int status)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        fixed (byte* pInput = inputToken)
        {
            byte* outPtr;
            uint outLen;
            
            status = NativeMethods.ntlm_server_parse_token(_handle, pInput, (uint)inputToken.Length, &outPtr, &outLen);

            if (status == 0x00090312) // SEC_I_CONTINUE_NEEDED
            {
                if (outPtr != null && outLen > 0)
                {
                    byte[] managedArray = new byte[outLen];
                    Marshal.Copy((IntPtr)outPtr, managedArray, 0, (int)outLen);
                    return managedArray;
                }
            }
            else if (status == 0) // SEC_E_OK
            {
                // Identity is ready
                return null;
            }
            
            return null;
        }
    }

    public (string Username, string Domain, string Workstation) GetIdentity()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NtlmIdentity id = NativeMethods.ntlm_server_get_identity(_handle);

        string username = (id.username != null && id.username_len > 0) 
            ? new string((char*)id.username, 0, (int)id.username_len) 
            : string.Empty;

        string domain = (id.domain != null && id.domain_len > 0) 
            ? new string((char*)id.domain, 0, (int)id.domain_len) 
            : string.Empty;

        string workstation = (id.workstation != null && id.workstation_len > 0) 
            ? new string((char*)id.workstation, 0, (int)id.workstation_len) 
            : string.Empty;

        return (username, domain, workstation);
    }

    public int Verify(byte[] ntHash)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ntHash.Length != 16) throw new ArgumentException("NT hash must be 16 bytes.");

        fixed (byte* pHash = ntHash)
        {
            return NativeMethods.ntlm_server_verify(_handle, pHash);
        }
    }

    /// <summary>
    /// Computes the NT hash (MD4 of the UTF-16LE encoded password) for a given password string.
    /// </summary>
    /// <param name="password">The plaintext password to hash.</param>
    /// <returns>A 16-byte NT hash of the password.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="password"/> is null.</exception>
    /// <exception cref="CryptographicException">Thrown if the native hash function returns an error.</exception>
    public static byte[] NtlmHashPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        // Encode as null-terminated UTF-16LE
        byte[] utf16Bytes = Encoding.Unicode.GetBytes(password + '\0');
        byte[] hash = new byte[16];

        try
        {
            fixed (byte* pUtf16 = utf16Bytes)
            fixed (byte* pHash = hash)
            {
                int result = NativeMethods.ntlm_hash_password(pHash, (ushort*)pUtf16);
                if (result != 0)
                {
                    throw new CryptographicException($"ntlm_hash_password failed with error code 0x{result:X8}.");
                }
            }
        }
        finally
        {
            // Zero out the UTF-16 bytes to limit exposure of the plaintext password in memory
            CryptographicOperations.ZeroMemory(utf16Bytes);
        }

        return hash;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            // Free the unmanaged Rust handle
            if (_handle != null)
            {
                NativeMethods.ntlm_server_destroy(_handle);
                _handle = null;
            }
            _disposed = true;
        }
    }

    ~SspiSession()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}