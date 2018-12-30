using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Il2CppDumper
{


    [StructLayout(LayoutKind.Sequential)]

    public class NSO_RelativeExtent
    {
        public int RegionRODataOffset;
        public int RegionSize;
    }

    public class NSO_SegmentHeader
    {
        public int FileOffset;
        public int MemoryOffset;
        public int DecompressedSize;
    }

    public class NSO_HEADER
    {
        public const int SIZE = 0x100;
        public const uint ExpectedMagic = 0x304F534E; // NSO0
        public bool Valid => Magic == ExpectedMagic;

        // Structure below

        public uint Magic;
        public uint Version;
        public uint Reserved;
        public uint Flags;

        public NSO_SegmentHeader HeaderText;
        public int ModuleOffset;
        public NSO_SegmentHeader HeaderRO;
        public int ModuleFileSize;
        public NSO_SegmentHeader HeaderData;
        public int BssSize;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] DigestBuildID;

        public int SizeCompressedText;
        public int SizeCompressedRO;
        public int SizeCompressedData;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x1C)]
        public byte[] Padding;

        public NSO_RelativeExtent APIInfo;
        public NSO_RelativeExtent DynStr;
        public NSO_RelativeExtent DynSym;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] HashText;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] HashRO;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
        public byte[] HashData;
    }

}
