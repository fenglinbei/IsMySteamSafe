using System.Buffers.Binary;

namespace IsMySteamSafe.Core.Inspection;

public sealed record MediaProbe(bool Complete, long TrailingBytes, string? TailKind);

/// <summary>Bounded top-level MP4 structure probe, never decodes or executes media.</summary>
public static class MediaStructureProbe
{
    public static async Task<MediaProbe> InspectAsync(Stream stream, CancellationToken token)
    {
        long offset = 0;
        byte[] header = new byte[16];
        bool sawFtyp = false;
        for (int boxes = 0; boxes < 4096 && offset + 8 <= stream.Length; boxes++)
        {
            token.ThrowIfCancellationRequested();
            stream.Position = offset;
            await stream.ReadExactlyAsync(header.AsMemory(0, 8), token);
            uint small = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            ulong size = small == 0 ? (ulong)(stream.Length - offset) : small;
            int headerSize = 8;
            if (small == 1)
            {
                if (stream.Length - offset < 16) break;
                await stream.ReadExactlyAsync(header.AsMemory(8, 8), token);
                size = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8)); headerSize = 16;
            }
            if (size < (ulong)headerSize || size > (ulong)(stream.Length - offset) ||
                header.Skip(4).Take(4).Any(b => b < 32 || b > 126)) break;
            sawFtyp |= header.AsSpan(4, 4).SequenceEqual("ftyp"u8);
            offset += (long)size;
            if (offset == stream.Length) return new(sawFtyp, 0, null);
        }
        stream.Position = offset;
        int read = await stream.ReadAsync(header, token);
        string? tail = read >= 4 && header.AsSpan(0, 2).SequenceEqual("MZ"u8) ? "可执行文件" :
            read >= 4 && (header.AsSpan(0, 2).SequenceEqual("PK"u8) || header.AsSpan(0, 4).SequenceEqual("Rar!"u8) ||
                header[0] == 0x37 && header[1] == 0x7a) ? "压缩内容" : null;
        return new(false, stream.Length - offset, tail);
    }
}
