using System.Runtime.InteropServices;

namespace Vortex.Sspi;

public unsafe class SspiSession
{
    public byte[]? ProcessToken(byte[] inputToken)
    {
        fixed (byte* pInput = inputToken)
        {
            // Call Rust
            var result = NativeMethods.process_token(pInput, (uint)inputToken.Length);

            if (result.status == 0 && result.out_ptr != null)
            {
                try
                {
                    // Copy data from Rust memory to a managed C# byte array
                    byte[] managedArray = new byte[result.out_len];
                    Marshal.Copy((IntPtr)result.out_ptr, managedArray, 0, (int)result.out_len);
                    return managedArray;
                }
                finally
                {
                    // CRITICAL: Tell Rust to free the buffer it allocated
                    NativeMethods.free_buffer(result.out_ptr, result.out_len);
                }
            }

            return null;
        }
    }
}