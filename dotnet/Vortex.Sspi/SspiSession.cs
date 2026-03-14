using System;
using System.Runtime.InteropServices;
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