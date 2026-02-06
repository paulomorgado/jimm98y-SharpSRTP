using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace SharpSRTP
{
    internal static class ArraySegmentExtensions
    {
#if !NET8_0_OR_GREATER
        public static ArraySegment<T> Slice<T>(this ArraySegment<T> source, int index)
        {
            if (source.Array == null)
            {
                throw new InvalidOperationException();
            }

            if ((uint)index > (uint)source.Count)
            {
                throw new ArgumentOutOfRangeException();
            }

            return new ArraySegment<T>(source.Array, source.Offset + index, source.Count - index);
        }

        public static ArraySegment<T> Slice<T>(this ArraySegment<T> source, int index, int count)
        {
            if (source.Array == null)
            {
                throw new InvalidOperationException();
            }

            if ((uint)index > (uint)source.Count || (uint)count > (uint)(source.Count - index))
            {
                throw new ArgumentOutOfRangeException();
            }

            return new ArraySegment<T>(source.Array, source.Offset + index, count);
        }
#endif
    }
}
