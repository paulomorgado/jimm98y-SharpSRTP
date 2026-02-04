using System;
using System.Runtime.CompilerServices;

#if !NET8_0_OR_GREATER
internal static partial class GC
{
    /// <summary>
    /// Allocate an array while skipping zero-initialization if possible.
    /// </summary>
    /// <typeparam name="T">Specifies the type of the array element.</typeparam>
    /// <param name="length">Specifies the length of the array.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)] // forced to ensure no perf drop for small memory buffers (hot path)
    public static T[] AllocateUninitializedArray<T>(int length) // T[] rather than T?[] to match `new T[length]` behavior
    {
        return new T[length];
    }
}
#endif
