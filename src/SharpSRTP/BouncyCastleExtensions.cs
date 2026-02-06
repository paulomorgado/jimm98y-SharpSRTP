using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Runtime.CompilerServices;

namespace SharpSRTP
{
    public static class BouncyCastleExtensions
    {
#if NET8_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter ToKeyParameter(this ReadOnlyMemory<byte> key)
        {
            return new KeyParameter(key.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static KeyParameter ToKeyParameter(this ReadOnlySpan<byte> key)
        {
            return new KeyParameter(key);
        }
#else
        public static KeyParameter ToKeyParameter(this ReadOnlyMemory<byte> memory)
        {
            if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment))
            {
                return new KeyParameter(segment.Array, segment.Offset, segment.Count);
            }
            // Fallback for non-array-backed memory
            return new KeyParameter(memory.ToArray());
        }
#endif
        public static KeyParameter ToKeyParameter(this ArraySegment<byte> key)
        {
            return new KeyParameter(key.Array, key.Offset, key.Count);
        }
    }
}
