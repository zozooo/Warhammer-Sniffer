// sniffer for incoming packets from warhammer servers.
// by zozooo

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace sniff
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, UIntPtr nSize, ref uint lpNumberOfBytesWritten);


        public static IniFile ini = new IniFile(".\\config.ini");


        public static bool Filter(string op)
        {
            string[] OpcodeFilter = ini.IniReadValue("Filter", "OpcodeFilter").Split(',');
            string ignore = ini.IniReadValue("Filter", "IgnoreType");
            if (ignore != "3")
            {
                foreach (string code in OpcodeFilter)
                {
                    if (code.ToLower() == op.ToLower())
                    {
                        if (ignore == "1")
                            return false;

                        if (ignore == "2")
                            return true;
                    }
                }
                if (ignore == "2")
                    return false;
            }
            return true;
        }

        public static byte[] readbytes(IntPtr Handle,int addr,int size)
        {
            byte[] bytestoread = new byte[size];
            uint rw = 0;
            ReadProcessMemory(Handle, (IntPtr)addr, bytestoread, (UIntPtr)size, ref rw);
            return bytestoread;
        }

        public static string bitc(byte[] s)
        {
            return BitConverter.ToString(s).Replace("-", "");
        }

        public static int ToInt32(string hex)
        {
            try
            {
                return Convert.ToInt32(hex, 16);
            }
            catch {  }
            return 0;
        }

        public static void writer(string s, string filename)
        {
            StreamWriter tw;

            if (!File.Exists(filename))
            {
                tw = new StreamWriter(filename);
            }
            else
            {
                tw = File.AppendText(filename);
            }
            tw.WriteLine(s);
            tw.WriteLine("\r\n");
            tw.Close();

        }


        public static string dumpbox(int size, string opcode, byte[] data)
        {
            string output = "";
            byte[] packet = data;
            string opname = Enum.GetName(typeof(Opcodes), ToInt32(opcode));
            if (opname == null) { opname = "UNKNOWN"; }
            output = String.Format("[Server]: Opcode = 0x{0} {1} PacketSize = {2} \r\n", opcode, opname, packet.Length);
            output += "|------------------------------------------------|----------------|\r\n";
            output += "|00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |0123456789ABCDEF|\r\n";
            output += "|------------------------------------------------|----------------|\r\n";
            int countpos = 0;
            int charcount = 0;
            int charpos = 0;
            int line = 1;

            if (size > 0)
            {
                output += "|";
                for (int count = 0; count < size; count++)
                {
                    if (line == 0) { output += "|"; line = 1; }
                    output += packet[count].ToString("X2") + " ";
                    countpos++;
                    if (countpos == 16)
                    {
                        output += "|";
                        for (int c = charcount; c < size; c++)
                        {
                            if (((int)packet[charcount] < 32) || ((int)packet[charcount] > 126))
                            {
                                output += ".";
                            }
                            else { output += (char)packet[charcount]; }

                            charcount++;
                            charpos++;
                            if (charpos == 16)
                            {
                                charpos = 0;
                                break;
                            }
                        }
                        if (charcount < size) { output += "|\r\n"; } else { output += "|"; }
                        countpos = 0;
                        line = 0;
                    }
                }
                if (countpos < 16)
                {
                    for (int k = 0; k < 16 - countpos; k++)
                    { output += "   "; }
                }
                if (charcount < size)
                {
                    output += "|";

                    for (int c = charcount; c < size; c++)
                    {
                        output += ".";
                        charcount++;
                        charpos++;
                    }

                    if (charpos < 16)
                    {
                        for (int j = 0; j < 16 - charpos; j++)
                        { output += " "; }
                    }
                    output += "|";
                }
            }

            output += "\r\n-------------------------------------------------------------------";
            
            return output;

        }
        static void Main(string[] args)
        {
            try
            {
                Process[] Processes = Process.GetProcessesByName("war");

                Process WARHAMMER = Processes[0];

                IntPtr readHandle = OpenProcess(0x10, false, (uint)WARHAMMER.Id);

                string filename = "packet_d" + DateTime.Now.ToString("dd") + "h" + DateTime.Now.ToString("hh") + "m" + DateTime.Now.ToString("mm") + ".txt";

                int opaddr = ToInt32(ini.IniReadValue("Offsets", "OpcodeAddress"));
                int sizeaddr = ToInt32(ini.IniReadValue("Offsets", "SizeAddress"));
                int msgaddr = ToInt32(ini.IniReadValue("Offsets", "MessageAdress"));


                string lastmsg = "";
                while (true)
                {

                    string opcode = bitc(readbytes(readHandle, opaddr, 1));
                    int size = ToInt32(bitc(readbytes(readHandle, sizeaddr, 2)));
                    byte[] data = readbytes(readHandle, msgaddr, size);
                    string msg = bitc(data);


                    if (msg != lastmsg && Filter("0x" + opcode) == true)
                    {

                        string packet = dumpbox(size, opcode, data);

                        string opname = Enum.GetName(typeof(Opcodes), ToInt32(opcode));
                        if (opname == null) { opname = "UNKNOWN"; }

                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write(" " + opname.PadRight(25) + " | Opcode = 0x" + opcode);
                        Console.WriteLine("  | Size = " + data.Length + "\r");
                        writer(packet, filename);
                        lastmsg = msg;
                    }
                }
            }
            catch (Exception e) {
                Console.WriteLine("make sure warhammer is running.\r\n\n\n\n\n");
                Console.WriteLine(e);
                Console.ReadLine();
            }
        }
    }
}
