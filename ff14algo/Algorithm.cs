//供开发调试使用，实际使用时请删掉
//#define DEBUG_ALGORITHM

using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace ff14algo
{
    internal class Algorithm
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr HDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, ref uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        private static readonly byte[] boundTable = new byte[] {
            0xA9, 0xB8, 0x85, 0x39, 0x16, 0xDD, 0x0B, 0xDD, 0x5A, 0x66, 0xC9, 0xAD, 0x5D, 0xE6, 0x87, 0x8C,
            0x1C, 0x2C, 0x82, 0x11, 0x12, 0xE1, 0xB8, 0xD5, 0x5E, 0x20, 0xC5, 0x0C, 0xE3, 0x6B, 0x4D, 0x8E,
            0xC8, 0x71, 0xCD, 0x00, 0xA5, 0x6D, 0x8C, 0xDC, 0x87, 0x82, 0x3E, 0x33, 0x41, 0xF8, 0x1E, 0x4B,
            0xE2, 0xD2, 0x1E, 0x96, 0x72, 0x3B, 0x78, 0xD3, 0x0A, 0xDF, 0x0A, 0xD7, 0xD4, 0x27, 0xBD, 0xBD,
            0x71, 0x3B, 0xD7, 0xC6, 0x4A, 0x60, 0x63, 0xF9, 0x26, 0x1C, 0x7A, 0x0B, 0x75, 0x85, 0xF8, 0x6E,
            0x34, 0x31, 0xE0, 0x40, 0x99, 0x65, 0xB7, 0x2B, 0xA2, 0x66, 0x2A, 0x07, 0xA7, 0x98, 0xE9, 0x78,
            0x2C, 0x97, 0xE1, 0xE3, 0x25, 0xE0, 0xE1, 0xF6, 0xED, 0xF5, 0x53, 0x38, 0xF2, 0x3E, 0x1E, 0x6C,
            0x72, 0x7B, 0x93, 0x00, 0xD6, 0x69, 0x81, 0x4D, 0xAD, 0xF8, 0x24, 0xA3, 0xAC, 0x01, 0x91, 0x8B
        };
        private static readonly short[] xorList = new short[] { 0xDD, 0xD6, 0xD8, 0xEA, 0xFD, 0xF6, 0xF8, 0xCA };
        //长度27*2, 两个字节表示一个hash函数的参数, [0,26]
        private static readonly byte[] hashTable = new byte[] {
            27, 5,
            28, 4,
            7, 6,
            7, 7,
            15, 2,
            27, 25,
            29, 14,
            13, 9,
            21, 2,
            5, 8,
            14, 11,
            13, 11,
            26, 11,
            25, 11,
            24, 11,
            23, 11,
            22, 11,
            21, 11,
            20, 11,
            23, 8,
            10, 9,
            15, 5,
            16, 5,
            18, 5,
            7, 3,
            5, 6,
            10, 5
        };

        //与随机化有关的
        private bool randomize = true;
        private uint defaultHashIndex = 0;
        private byte defaultLaunchCode = 0x0;

        //hex2byte
        public byte[] Hex2byte(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                throw new Exception();
            }
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
            {
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return returnBytes;
        }

        //str2byte
        public byte[] String2byte(string data, bool reverse = false)
        {
            byte[] buf = System.Text.Encoding.GetEncoding("utf-8").GetBytes(data);
            if (buf == null) throw new Exception();
            if (reverse)
            {
                return buf.Reverse().ToArray();
            }
            return buf;
        }

        //获取本机CPUID
        private byte[] GetCpuId()
        {
            byte[] cpuBytes = new byte[0x8];
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return cpuBytes;
            }

            try
            {
                var asmCode = new CpuIdAssemblyCode();
                CpuIdAssemblyCode.CpuIdInfo info = new CpuIdAssemblyCode.CpuIdInfo();
                asmCode.Call(1, ref info);
                BitConverter.GetBytes(info.Eax).CopyTo(cpuBytes, 0);
                BitConverter.GetBytes(info.Edx).CopyTo(cpuBytes, 4);
                return cpuBytes;
            }
            catch
            {
                throw new Exception();
            }
        }

        //获取网卡MacAddr
        private byte[] GetMacAddress()
        {
            byte[] result = new byte[0x6];
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return result;
            }

#pragma warning disable CS8600 // 将 null 字面量或可能为 null 的值转换为非 null 类型。
            RegistryKey regkey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards");
#pragma warning restore CS8600 // 将 null 字面量或可能为 null 的值转换为非 null 类型。
#pragma warning disable CS8602 // 解引用可能出现空引用。
#pragma warning disable CS8600 // 将 null 字面量或可能为 null 的值转换为非 null 类型。
            using (RegistryKey firstSubKey = regkey.OpenSubKey(regkey.GetSubKeyNames()[0]))
            {
#pragma warning disable CS8600 // 将 null 字面量或可能为 null 的值转换为非 null 类型。
                string networkInterface = firstSubKey.GetValue("ServiceName").ToString();
#pragma warning restore CS8600 // 将 null 字面量或可能为 null 的值转换为非 null 类型。
#pragma warning disable CS8604 // 引用类型参数可能为 null。
                Hex2byte(SubGetMacAddress(networkInterface)).CopyTo(result, 0);
            }
#pragma warning restore CS8602 // 解引用可能出现空引用。
#pragma warning restore CS8604 // 引用类型参数可能为 null。

            return result;
        }

        //获取网卡MacAddr
        private string SubGetMacAddress(string NicId)
        {
            System.IntPtr hDevice = CreateFile("\\\\.\\" + NicId, 0x80000000 | 0x40000000, 0, IntPtr.Zero, 3, 4, IntPtr.Zero);

            if (hDevice.ToInt32() == -1)
            {
                return "";
            }

            uint Len = 0;
            IntPtr Buffer = Marshal.AllocHGlobal(256);

            Marshal.WriteInt32(Buffer, 0x01010101);

            if (!DeviceIoControl(hDevice, 0x170002, Buffer, 4, Buffer, 256, ref Len, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(Buffer);
                CloseHandle(hDevice);
                return "";
            }

            byte[] macBytes = new byte[6];
            Marshal.Copy(Buffer, macBytes, 0, 6);

            Marshal.FreeHGlobal(Buffer);
            CloseHandle(hDevice);
            return new System.Net.NetworkInformation.PhysicalAddress(macBytes).ToString();
        }

        //获取MD5值
        private byte[] GetMD5(byte[] payload)
        {
            MD5? check = MD5.Create();
            byte[]? md5Bytes = check.ComputeHash(payload);
            return md5Bytes;
        }

        //默认index=0;networkAddr.Length = 6;返回hash值
        public uint GenerateSectionHash(byte[] dynamicKey, byte[] networkAddr, byte[] cpuId, ref uint hashIndex)
        {
            hashIndex = defaultHashIndex;
            if (randomize)
            {
                Random rd = new();
                hashIndex = (uint)rd.Next(0, 26);
            }

            //little check
            if (hashIndex*2 + 1 > hashTable.Length)
            {
#if DEBUG_ALGORITHM
                Console.WriteLine("[GenerateSectionHash]hashIndex too large.");
#endif
                hashIndex = 0;
            }

            if (dynamicKey.Length != 20)
            {
                throw new Exception("dynamicKey.Length != 20");
            }

            if (networkAddr.Length != 6)
            {
                throw new Exception("networkAddr.Length != 6");
            }

            //prepare data
            byte[] data = new byte[dynamicKey.Length + networkAddr.Length + 4 * 2];
            dynamicKey.CopyTo(data, 0);
            networkAddr.CopyTo(data, dynamicKey.Length);
            cpuId.CopyTo(data, dynamicKey.Length + networkAddr.Length);

            //start hashing

            //务必使用uint类型，以进行逻辑移位，如果不使用uint，hash右移只执行算术移位，导致结果不同
            uint hash = (uint)data.Length;

            int p1 = hashTable[hashIndex * 2];
            int p2 = hashTable[hashIndex * 2 + 1];

            for (int i = 0; i < data.Length; i++)
            {
                hash =  (hash >> p1) ^ (hash << p2) ^ data[i];
            }

            hash &= 0x7FFFFFFF;

#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[GenerateSectionHash] Hashed Index:{0}, Value:{1}", hashIndex, hash));
#endif
            return hash;
        }

        //创建动态码表
        private byte[] GenerateTable(byte random)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[GenerateTable] random{0}", random));
#endif
            byte[] rawData = { random };
            byte[] mdResult = GetMD5(rawData);
            byte[] table = new byte[16];
            for (int i = 0; i < 0x100; i++)
            {
                uint cflag = 0;
                for (int j = 0; j < mdResult.Length; j++)
                {
                    cflag += (uint)(table[15 - j] + mdResult[15 - j]);
                    table[15 - j] = (byte)cflag;
                    cflag >>= 8;
                }
            }
            return table;
        }

        //返回扩增后的（len = 256）
        private byte[] SubExpansion(byte[] data, byte[] baseData)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[SubExpansion] data.len:{0}, baseData.len:{1}", data.Length, baseData.Length));
#endif
            byte[] result = new byte[256];

            uint eax, ebx = 0, ecx, edx, esi, edi;
            uint lastData, esp_0x2C, esp_0x20, esp_0x38;

            for (int i = 0; i < 32; i++)
            {
                eax = BitConverter.ToUInt32(data, i*4);
                lastData = 0;
                ecx = eax;
                eax &= 0xFFFF;
                ecx >>= 0x10;
                esp_0x2C = ecx;
                esp_0x20 = eax;

                for (int j = 0; j < 32; j++)
                {
                    eax = BitConverter.ToUInt32(baseData, j*4);
                    edx = esp_0x20;
                    esi = ecx & 0xFFFF;
                    ecx = eax;
                    ecx >>= 0x10;
                    eax &= 0xFFFF;
                    edi = ecx & 0xFFFF;
                    edx *= eax;
                    ecx = esp_0x20;
                    esp_0x38 = ebx;
                    ecx *= edi;
                    ebx = esi & 0xFFFF;
                    eax *= ebx;
                    esi = ebx * edi;
                    eax += ecx;
                    edi = (eax >= ecx) ? esp_0x38 : 0x10000;
                    ecx = eax;
                    ecx <<= 0x10;
                    edx += ecx;
                    eax >>= 0x10;
                    if (edx < ecx)
                    {
                        edi++;
                    }
                    eax+=edi;
                    esi+=eax;
                    eax = lastData;
                    uint tmp = BitConverter.ToUInt32(result, (i + j) * 4);
                    tmp += eax;

                    eax = (tmp < eax) ? 1u : 0;

                    tmp += edx;

                    BitConverter.GetBytes(tmp).CopyTo(result, (i + j) * 4);
#if DEBUG_ALGORITHM
            Console.Write(string.Format("[i:{0}, j:{1}, tmp:{2}] ",i , j, tmp));
#endif
                    if (tmp < edx)
                    {
                        eax++;
                    }
                    eax+=esi;
                    lastData = eax;
                    ebx = 0;
                    ecx = esp_0x2C;
                }

#if DEBUG_ALGORITHM
                Console.WriteLine("\n\n");
#endif

                BitConverter.GetBytes(eax).CopyTo(result, (i + 32) * 4);
            }
#if DEBUG_ALGORITHM
            Console.WriteLine("\n\n\n");
#endif
            return result;
        }

        //返回处理后的Key
        private byte[] obfuscateKey(byte[] reversedTable, byte[] keyExpanded, uint magic, int mainCounter, ref uint processedMagic)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[obfuscateKey] mainCounter:{0}, magic:{1}", mainCounter, magic));
#endif
            if (reversedTable.Length != 0x80)
            {
                throw new Exception();
            }

            if (keyExpanded.Length != 0x100)
            {
                throw new Exception();
            }

            byte[] keyLocal = new byte[0x100];
            keyExpanded.CopyTo(keyLocal, 0);

            uint store;
            uint _ebp_;
            uint mix;
            uint edi = 0;
            for (int i = 0; i < 0x20; i++)
            {
                uint eax, ebx, ecx, edx, esi;

                mix = edi;

                ecx = magic; // magic
                esi = ecx;
                eax = BitConverter.ToUInt32(reversedTable, i*4);
                edi = eax;
                ecx &= 0xFFFF;
                eax &= 0xFFFF;
                edx = ecx;
                edx *= eax;
                esi >>= 0x10;
                edi >>= 0x10;
                ecx*= edi;
                ebx = esi & 0xFFFF;
                eax *= ebx;
                esi = ebx;
                esi *= edi;
                eax += ecx;
                edi = 0x10000;
                if (eax >= ecx)
                {
                    edi = 0;
                }
                ecx = eax;
                ecx <<= 0x10;
                edx += ecx;
                eax >>= 0x10;
                store = edx;
                if (edx < ecx)
                {
                    eax++;
                }
                esi += eax;
                esi += edi;
                _ebp_ = esi;

                edi = mix;

                uint proc = BitConverter.ToUInt32(keyLocal, 124 + 4 * (i - (mainCounter-1)));
                eax = proc;
                edx |= 0xFFFFFFFF;
                eax -= edi;
                edx -= edi;
                if (edx < eax)
                {
                    edi = 0xFFFFFFFF;
                }
                else
                {
                    edi = 0;
                }
                proc = eax;
                eax = store;
                proc -= eax;
                BitConverter.GetBytes(proc).CopyTo(keyLocal, 124 + 4 * (i - (mainCounter-1)));
#if DEBUG_ALGORITHM
                Console.Write(string.Format("[ite:{0}, proc:{1}] ", i,  proc));
#endif
                ecx = proc;
                edx |= 0xFFFFFFFF;
                edx -= eax;
                edi = ~edi + 1;

                if (ecx > edx)
                {
                    edi++;
                }
                edi += _ebp_;
            }

            processedMagic = edi;
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[final:processedMagic:{0}]", processedMagic));
            Console.WriteLine("\n\n\n");
#endif
            return keyLocal;
        }

        //算法II
        private static byte[] KeySubTable(byte[] key, byte[] table, int j, ref uint ret_eax)
        {
            byte[] expanded = new byte[key.Length];
            key.CopyTo(expanded, 0);
            //使用码表替换并做减法
            uint t_eax = 0, t_ecx, t_ebp;
            for (int k = 0; k<0x20; k++)
            {
                t_ecx = BitConverter.ToUInt32(expanded, 120 + 4*k - (j-2)*4);
                t_ecx -= t_eax;
                t_eax = BitConverter.ToUInt32(table, 4*k);
                t_ebp = 0xffffffff;
                t_ecx -= t_eax;
                t_ebp -= t_eax;

                if (t_ebp < t_ecx)
                {
                    t_eax = 1;
                }
                else
                {
                    t_eax = 0;
                }


                BitConverter.GetBytes(t_ecx).CopyTo(expanded, 120 + 4*k - (j-2)*4);
            }
            ret_eax = t_eax;
            return expanded;
        }

        //算法II
        private byte[] KeyContraction(byte[] key, byte[] dynamicTable)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[KeyContraction] key.len:{0}, dynamicTable.len:{1}", key.Length, dynamicTable.Length));
#endif
            byte[] expanded = new byte[key.Length];
            key.CopyTo(expanded, 0);
            uint esp_0x10 = BitConverter.ToUInt32(dynamicTable, 124);
            uint esp_0x28;
            uint esp_0x14;
            uint eax, ebx, ecx, edx, ebp, esi, edi;
            uint save_0x100;
            uint esp_0x30;
            for (int j = 0; j<0x21; j++)
            {
                edx = esp_0x10;
                if (j == 0)
                {
                    ebp = 0;
                }
                else
                {
                    ebp = BitConverter.ToUInt32(expanded, expanded.Length - 4 * j);
                }
                ecx = BitConverter.ToUInt32(expanded, expanded.Length - 4 * (j+1));


                edx++;
                esi = edx;
                esi >>= 0x10;
                esp_0x10 = edx;
                esp_0x28 = esi;
                eax = ebp;
                if (eax == esi)
                {
                    eax >>= 0x10;
                    esp_0x14 = eax;
                }
                else
                {
                    edi = esi & 0xffff;
                    edi++;
                    eax /= edi;
                    edx = eax & 0xffff;
                    esp_0x14 = edx;
                    eax = edx;
                    edx = esp_0x10;
                }

                eax &= 0xffff;
                edi = edx & 0xffff;
                esi &= 0xffff;
                edx = edi;
                edx *= eax;
                eax *= esi;
                esp_0x30 = eax;
                ebx = edx;
                ebx <<= 0x10;
                eax |= 0xffffffff;
                ecx -= ebx;
                eax -= ebx;
                if (ecx > eax)
                {
                    ebp--;
                }
                edx >>= 0x10;
                edx += esp_0x30;
                ebp -= edx;
                edx = 1;

                while (true)
                {
                    if (ebp <= esi)
                    {
                        if (ebp != esi)
                        {
                            break;
                        }
                        eax = edi;
                        eax >>= 0x10;
                        if (ecx < eax)
                        {
                            break;
                        }
                    }

                    eax=edi;
                    eax<<=0x10;
                    ebx |= 0xffffffff;
                    ecx-=eax;
                    ebx-=eax;
                    if (ecx > ebx)
                    {
                        ebp-=edx;
                    }
                    ebp-=esi;

                    esp_0x14+=edx;
                }
                edx = 0xffff;
                uint cmptmp = esp_0x28 & 0xffff;
                if (cmptmp == edx)
                {
                    ebx = ebp & 0xffff;
                }
                else
                {
                    eax = ecx;
                    edx = ebp;
                    edx <<= 0x10;
                    eax >>= 0x10;
                    eax += edx;
                    ebx = esi+1;
                    edx = 0;
                    eax /= ebx;
                    ebx = eax & 0xffff;
                }
                eax = ebx & 0xffff;
                edi *= eax;
                eax *= esi;
                edx |= 0xffffffff;
                ecx -= edi;
                edx -= edi;
                if (ecx > edx)
                {
                    ebp--;
                }
                edx = eax;
                edx <<= 0x10;
                esi |= 0xffffffff;
                ecx -= edx;
                esi -= edx;
                if (ecx > esi)
                {
                    ebp--;
                }

                eax >>= 0x10;
                ebp -= eax;
                eax = esp_0x10;

                while (true)
                {
                    if (ebp == 0)
                    {
                        if (ecx < eax)
                        {
                            break;
                        }
                    }
                    edx |= 0xffffffff;
                    ecx -= eax;
                    edx -= eax;
                    if (ecx > edx)
                    {
                        ebp--;
                    }
                    ebx++;
                }

                edi = esp_0x14;
                ecx = ebx & 0xffff;
                edi <<= 0x10;
                edi += ecx;
                eax--;
                esp_0x10 = eax;
                eax = esi;
                //这里传EDI

                if (edi != 0)
                {
                    byte[] obfuscated = obfuscateKey(dynamicTable, expanded, edi, j, ref eax);
                    if (obfuscated.Length != 0x100) throw new Exception();
                    obfuscated.CopyTo(expanded, 0);
                }
                else
                {
                    eax = 0;
                }

                while (true)
                {
                    save_0x100 = 0;
                    if (j != 0)
                    {
                        save_0x100 = BitConverter.ToUInt32(expanded, expanded.Length - 4 * j);
                        save_0x100 -= eax;
                        BitConverter.GetBytes(save_0x100).CopyTo(expanded, expanded.Length - 4 * j);
                    }

                    bool needSub = false;
                    if (save_0x100 == 0)
                    {
                        eax = esi;
                        esi = ebp;
                        ecx = BitConverter.ToUInt32(expanded, expanded.Length - 4*(j+1));
                        edx = BitConverter.ToUInt32(dynamicTable, 124);
                        if (ecx <= edx)
                        {
                            if (ecx < edx)
                            {
                                break;
                            }

                        }
                        else
                        {
                            needSub = true;
                        }
                    }
                    else
                    {
                        needSub = true;

                    }
                    if (needSub)
                    {
                        KeySubTable(expanded, dynamicTable, j, ref eax).CopyTo(expanded, 0);
                    }

                }
            }

            return expanded;
        }

        //算法II
        private byte[] KeyExpansion(byte[] password, byte[] dynamicKey)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[KeyExpansion] password.len:{0}, dynamicKey.len:{1}", password.Length, dynamicKey.Length));
#endif
            //prepare data
            byte[] key = new byte[dynamicKey.Length + password.Length];
            dynamicKey.CopyTo(key, 0);
            password.CopyTo(key, dynamicKey.Length);

            //get table & check length

            byte[] dynamicTable;
            if (randomize)
            {
                Random rd = new();
                byte randomIndex = (byte)(rd.Next() & 0xFF);
                dynamicTable = GenerateTable(randomIndex);
            }
            else
            {
                dynamicTable = GenerateTable(defaultLaunchCode);
            }

            if (dynamicTable.Length != 16 || password.Length >= 30) //passwordMaxLen = 30
            {
                throw new Exception();
            }

            byte[] magic = new byte[2];
            magic[0] = 0;
            magic[1] = 2;

            //make magic expanded
            for (int i = 0; i<16; i++)
            {
                byte[] tmpTable = new byte[16];
                dynamicTable.CopyTo(tmpTable, 0);
                if (i != 0)
                {
                    for (int j = 0; j<tmpTable.Length; j++)
                    {
                        if (tmpTable[15-j] == 0 && j<=15)
                        {
                            tmpTable[14-j]+=1;
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }

                    tmpTable[15] = (byte)i;
                }
                byte[] tmpMd5 = GetMD5(tmpTable);
                for (int j = 0; j<16; j++)
                {
                    //cut 0x00
                    if (magic != null && tmpMd5 != null && tmpMd5[j]!= 0)
                    {
                        List<byte> tmp = magic.ToList();
                        tmp.Add(tmpMd5[j]);
                        magic=tmp.ToArray();
                    }
                }
            }
            if (magic == null || magic.Length < 128)
            {
                throw new Exception();
            }
            key.CopyTo(magic, 128 - key.Length);
            magic[128 - key.Length - 1] = 0;

            //cut magic
            byte[] data = new byte[128];
            Array.Copy(magic, data, 128);
            data.Reverse().ToArray().CopyTo(data, 0);

            dynamicTable = boundTable;
            dynamicTable.Reverse().ToArray().CopyTo(dynamicTable, 0);

            byte[] procKey = new byte[256];

            //Key扩增
            SubExpansion(data, data).CopyTo(procKey, 0);
            //Key压缩
            KeyContraction(procKey, dynamicTable).CopyTo(procKey, 0);
            //Key二次扩增
            SubExpansion(procKey, data).CopyTo(procKey, 0);
            //Key二次压缩
            KeyContraction(procKey, dynamicTable).CopyTo(procKey, 0);

            //修剪Key
            byte[] resultKey = new byte[128];
            Array.Copy(procKey, resultKey, 128);
            resultKey.Reverse().ToArray().CopyTo(resultKey, 0);


            return resultKey;
        }

        //DES加密
        private string DESEncryption(byte[] dynamicKey, byte[] finalKeyInput)
        {
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[DESEncryption] dynamicKey.len:{0}, finalKeyInput.len:{1}", dynamicKey.Length, finalKeyInput.Length));
#endif
            if (dynamicKey.Length != 20)
            {
                return "dynamicKey.Length != 0x20";
            }

            string dynamicKeyIn = Encoding.Default.GetString(dynamicKey);


            short[] byteList = new short[8];

            int offset = 0;
            for (int i = 0; i < byteList.Length; i += 2)
            {
                int shit = int.Parse(dynamicKeyIn.Substring(offset, 5));
                byteList[i] = (short)(shit % 256);
                byteList[i + 1] = (short)(shit / 256);
                offset += 5;
            }

            string dynamicKeyOut = "";
            for (int i = 0; i < byteList.Length; ++i)
            {
                byteList[i] = (short)(byteList[i] ^ xorList[i]);
                byteList[i] = (byte)((16 * byteList[i]) | (byteList[i] >> 4) & 0xF);
                dynamicKeyOut += (char)byteList[i];
            }

            byte[] byteArr = finalKeyInput;

#pragma warning disable SYSLIB0021 // 类型或成员已过时
            DESCryptoServiceProvider des = new DESCryptoServiceProvider()
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                Key = Encoding.UTF8.GetBytes(dynamicKeyOut),
                IV = Encoding.UTF8.GetBytes("23456789")
            };
#pragma warning restore SYSLIB0021 // 类型或成员已过时

            return Convert.ToBase64String(des.CreateEncryptor().TransformFinalBlock(byteArr, 0, byteArr.Length));
        }

        //登陆密码加密
        public string LoginEncryption(string password, string dynamicKey)
        {
#if DEBUG_ALGORITHM
            //randomize = false;
            //defaultHashIndex = 0;
            //defaultLaunchCode = 0;
#endif
#if DEBUG_ALGORITHM
            Console.WriteLine(string.Format("[LoginEncryption] password:{0}, dynamicKey:{1}", password, dynamicKey));
#endif
            byte[] passIn = Encoding.Default.GetBytes(password);
            byte[] dyKeyIn = Encoding.Default.GetBytes(dynamicKey);
            if (passIn.Length == 0 || password.Length > 30)
            {

                return "";
            }

            if (dynamicKey.Length != 20)
            {
                return "";
            }

            byte[] finalKey = KeyExpansion(passIn, dyKeyIn);
            if (finalKey.Length != 0x80)
            {
                throw new Exception("finalKey.Length = 0x80");
            }

            byte[] netCard = GetMacAddress();
            byte[] cpuId = GetCpuId();

            uint hashIndex = 0;
            uint hashValue = GenerateSectionHash(dyKeyIn, netCard, cpuId, ref hashIndex);

            byte[] result = new byte[176];
            byte[] secI = { 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0 };
            secI.CopyTo(result, 0);

            finalKey.CopyTo(result, secI.Length);

            BitConverter.GetBytes(hashIndex).CopyTo(result, secI.Length + finalKey.Length);

            BitConverter.GetBytes(hashValue).CopyTo(result, secI.Length + finalKey.Length + 4);

            BitConverter.GetBytes(0xE).CopyTo(result, secI.Length + finalKey.Length + 8);

            netCard.CopyTo(result, secI.Length + finalKey.Length + 12);

            cpuId.CopyTo(result, secI.Length + finalKey.Length + 12 + netCard.Length);

            return DESEncryption(dyKeyIn, result);
        }

        internal sealed class CpuIdAssemblyCode
           : IDisposable
        {
            [StructLayout(LayoutKind.Sequential)]
            internal ref struct CpuIdInfo
            {
                public uint Eax;
                public uint Ebx;
                public uint Ecx;
                public uint Edx;

            }

            [DllImport("kernel32.dll", EntryPoint = "VirtualAlloc")]
            internal static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate void CpuIDDelegate(int level, ref CpuIdInfo cpuId);
            [DllImport("kernel32.dll", EntryPoint = "VirtualFree")]
            internal static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, int dwFreeType);

            private IntPtr _codePointer;
            private uint _size;
            private CpuIDDelegate _delegate;

            public CpuIdAssemblyCode()
            {
                byte[] codeBytes = (IntPtr.Size == 4) ? x86CodeBytes : x64CodeBytes;

                _size = (uint)codeBytes.Length;
                _codePointer = VirtualAlloc(IntPtr.Zero, new UIntPtr(_size), 0x1000 | 0x2000, 0x40);

                Marshal.Copy(codeBytes, 0, _codePointer, codeBytes.Length);
                _delegate = Marshal.GetDelegateForFunctionPointer<CpuIDDelegate>(_codePointer);
            }

            ~CpuIdAssemblyCode()
            {
                Dispose(false);
            }

            public void Call(int level, ref CpuIdInfo cpuInfo)
            {
                _delegate(level, ref cpuInfo);
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            private void Dispose(bool disposing)
            {
                VirtualFree(_codePointer, _size, 0x8000);
            }

            private readonly static byte[] x86CodeBytes = {
                0x55,                   // push        ebp  
                0x8B, 0xEC,             // mov         ebp,esp
                0x53,                   // push        ebx  
                0x57,                   // push        edi

                0x8B, 0x45, 0x08,       // mov         eax, dword ptr [ebp+8] (move level into eax)
                0x0F, 0xA2,              // cpuid

                0x8B, 0x7D, 0x0C,       // mov         edi, dword ptr [ebp+12] (move address of buffer into edi)
                0x89, 0x07,             // mov         dword ptr [edi+0], eax  (write eax, ... to buffer)
                0x89, 0x5F, 0x04,       // mov         dword ptr [edi+4], ebx 
                0x89, 0x4F, 0x08,       // mov         dword ptr [edi+8], ecx 
                0x89, 0x57, 0x0C,       // mov         dword ptr [edi+12],edx 

                0x5F,                   // pop         edi  
                0x5B,                   // pop         ebx  
                0x8B, 0xE5,             // mov         esp,ebp  
                0x5D,                   // pop         ebp 
                0xc3                    // ret
                };

            private readonly static byte[] x64CodeBytes = {
                0x53,                       // push rbx    this gets clobbered by cpuid

                // rcx is level
                // rdx is buffer.
                // Need to save buffer elsewhere, cpuid overwrites rdx
                // Put buffer in r8, use r8 to reference buffer later.

                // Save rdx (buffer addy) to r8
                0x49, 0x89, 0xd0,           // mov r8,  rdx

                // Move ecx (level) to eax to call cpuid, call cpuid
                0x89, 0xc8,                 // mov eax, ecx
                0x0F, 0xA2,                 // cpuid

                // Write eax et al to buffer
                0x41, 0x89, 0x40, 0x00,     // mov    dword ptr [r8+0],  eax
                0x41, 0x89, 0x58, 0x04,     // mov    dword ptr [r8+4],  ebx
                0x41, 0x89, 0x48, 0x08,     // mov    dword ptr [r8+8],  ecx
                0x41, 0x89, 0x50, 0x0c,     // mov    dword ptr [r8+12], edx

                0x5b,                       // pop rbx
                0xc3                        // ret
                };
        }
    }
}
