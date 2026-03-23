using Extensions;
using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows.Forms;

namespace DiskStationManager.SecureShell
{
    internal class DSMSession : ISecureShellSession, IDisposable
    {
        public event EventHandler HostKeyChange;

        private readonly DSMHost _host;
        private readonly ConnectionInfo _ci;
        private readonly IProxySettings _proxySettings;
        protected IDSMVersion _version = null;

        private readonly EventHandler _hostKeyChange;

        public static bool ConsoleUI { get; set; }

        private AuthenticationBannerEventArgs _banner;
        private void OnHostKeyChange(object sender, EventArgs e)
        {
            HostKeyChange?.Invoke(sender, e);
        }
        public DSMSession(DSMHost host, EventHandler hostKeyChange, IProxySettings proxy = null)
        {
            bool canceled = false;
            _hostKeyChange = hostKeyChange ?? throw new ArgumentNullException(nameof(hostKeyChange));
            HostKeyChange += _hostKeyChange;

            //RmExecutionMode = ConsoleCommandMode.InteractiveSudo;

            _host = host ?? throw new ArgumentNullException(nameof(host));

            _proxySettings = proxy;

            int i = 0;
            AuthenticationMethod[] methods = new AuthenticationMethod[host.AuthenticationSection.Count];
            foreach (var m in host.AuthenticationMethods)
            {
                methods[i++] = m.getAuthenticationMethod(host.UserName, host.StorePassPhrases, GetPassPhrase, GetInteractiveMethod, out canceled);
            }
            if (!canceled)
            {
                if (proxy != null)
                {
                    if (!Enum.TryParse(proxy.ProxyType, true, out ProxyTypes proxypath))
                    {
                        proxypath = ProxyTypes.None;
                    }
                    _ci = new ConnectionInfo(host.Host, host.Port, host.UserName, proxypath, proxy.Host, proxy.Port, proxy.UserName, proxy.Password, methods);
                }
                else
                {
                    _ci = new ConnectionInfo(host.Host, host.Port, host.UserName, methods);
                }

                _ci.AuthenticationBanner += AuthorizationBannerAction;

                foreach (var am in _ci.AuthenticationMethods)
                {
                    if (am is KeyboardInteractiveAuthenticationMethod kb)
                    {
                        kb.AuthenticationPrompt += AuthenticationPromptAction;
                    }
                }
            }
        }

        private string KeyFingerPrint(HostKeyEventArgs e)
        {
            return e.HostKeyName + " " + e.KeyLength + " " + e.FingerPrint.ToString(':').ToLower();
        }
        private string GetHostAddress(string nameOrAddress, out bool success)
        {
            success = false;
            string address = string.Empty;
            try
            {
                var iplist = Dns.GetHostAddresses(nameOrAddress);

                foreach (var ip in iplist)
                {
                    if (string.IsNullOrEmpty(address))
                    {
                        address = ip.ToString();
                    }
                    else
                    {
                        address += ";" + ip.ToString();
                    }
                }
                success = true;

            }
            catch (Exception)
            {
                address = "0.0.0.0";
            }
            return address;
        }
        private void SshClient_HostKeyReceived(object sender, HostKeyEventArgs e)
        {
            DialogResult trust = DialogResult.Yes;
            e.CanTrust = false; //we clicked yes if the fingerprint matches

            var host = _host;
            if (host.FingerPrint.Length.Equals(0) || !host.FingerPrint.SequenceEqual(e.FingerPrint))
            {
                string details = $"{_ci.Host}[{GetHostAddress(host.Host, out _)}]?\tKey fingerprint: {KeyFingerPrint(e)}\tServer version: {_ci.ServerVersion}"
                                .Replace("\t", $"{Environment.NewLine}{Environment.NewLine}");

                if (host.FingerPrint.Length.Equals(0))
                {
                    trust = InputBoxYesNoExclamation("Do you trust the new connection with host " + details,
                                                    $"New host key for {host.Host}.");
                }
                else
                {
                    trust = InputBoxYesNoExclamation("Do you trust the changed connection with host " + details,
                                                    $"The host key has changed for {host.Host}.");
                }

                if (trust == DialogResult.Yes)
                {
                    host.FingerPrint = e.FingerPrint;
                    OnHostKeyChange(this, new EventArgs());
                }
            }
            e.CanTrust = trust.Equals(DialogResult.Yes);
        }
        private DialogResult InputBoxYesNoExclamation(string text, string caption)
        {
            if (ConsoleUI)
            {
                string memo = Console.Title;
                try
                {
                    Console.Title = caption;
                    Console.WriteLine(caption);
                    Console.WriteLine(text);
                    Console.WriteLine();
                    Console.WriteLine("Please respond with yes or no (NO/yes):");
                    if (Console.ReadLine().ToLowerInvariant() == "yes") return DialogResult.Yes;

                }
                catch
                {

                }
                finally
                {
                    Console.Title = memo;
                }
                return DialogResult.No;
            }
            else
                return MessageBox.Show(text, caption, MessageBoxButtons.YesNo, MessageBoxIcon.Exclamation);
        }
        private string GetPassPhrase(FileInfo keyFile)
        {
            string result;
            using (PassPhrase dialog = new PassPhrase(keyFile))
            {
                dialog.ShowDialog();
                result = dialog.Password;
            }
            return result;
        }
        private string GetInteractiveMethod(DSMKeyboardInteractiveEventArgs e)
        {
            var banner = new List<string>();
            banner.AddRange(e.Banner.Split('\n'));
            banner.AddRange(e.Instruction.Split('\n'));

            string result;
            using (PassPhrase dialog = new PassPhrase(e.Username, banner.ToArray(), e.Id + ": " + e.Request))
            {
                dialog.ShowDialog();
                result = dialog.Password;
            }
            return result;
        }
        private string GetInteractiveMethod()
        {
            string result;
            using (PassPhrase dialog = new PassPhrase("you", new string[0], "ww"))
            {
                dialog.ShowDialog();
                result = dialog.Password;
            }
            return result;
        }
        private void WaitForHostKeyDuringAction<C>(C client, Action<C> action) where C : BaseClient
        {
            client.HostKeyReceived += SshClient_HostKeyReceived;
            action(client);
            client.HostKeyReceived -= SshClient_HostKeyReceived;
        }
        [Obsolete("This method is only present to support DSM versions below 6.x")]
        public void ClientExecuteAsRoot(Action<SshClient> action)
        {
            using (SshClient sc = new SshClient(_host.Host, "root", GetPassword())) WaitForHostKeyDuringAction(sc, action);
        }
        public void ClientExecute(Action<SshClient> action)
        {
            using (SshClient sc = new SshClient(_ci)) WaitForHostKeyDuringAction(sc, action);
        }
        public void ClientExecute(Action<ScpClient> action)
        {
            using (ScpClient sc = new ScpClient(_ci)) WaitForHostKeyDuringAction(sc, action);
        }

        public string Version
        {
            get
            {
                if (_version is null)
                {
                    ClientExecute(sc => GetConsole(sc));
                }
                return _version.Version;
            }
        }
        internal IConsoleCommand GetConsole(SshClient client)
        {
            IConsoleCommand console = null;
            EnsureConnection(client, ssh =>
            {
                console = BConsoleCommand.GetDSMConsole(ssh);
                _version = console.GetVersionInfo();
            });
            _version = console.GetVersionInfo();
            return console;
        }

        public ConnectionInfo ConnectionInfo => _ci;

        public DSMHost Host => _host;

        public IProxySettings Proxy => _proxySettings;

        public Func<string> GetPassword => ReturnPassword;
        private string ReturnPassword()
        {
            foreach (DSMAuthentication a in _host.AuthenticationMethods)
            {
                if (a.Method == DSMAuthenticationMethod.Password)
                {
                    return a.Password;
                }
            }
            return GetInteractiveMethod();
        }
        private void AuthorizationBannerAction(object sender, AuthenticationBannerEventArgs e)
        {
            _banner = e;
        }
        private void AuthenticationPromptAction(object sender, AuthenticationPromptEventArgs e)
        {
            System.Diagnostics.Debug.WriteLine("AuthenticationPromptAction");

            foreach (var p in e.Prompts)
            {
                p.Response = GetInteractiveMethod(new DSMKeyboardInteractiveEventArgs(_banner, e, p));
            }
        }
        public void UploadFile(string destinationPath, string sourcePath)
        {
            UploadFile(destinationPath, new FileInfo(sourcePath));
        }
        public static void UploadFile(ScpClient scpClient, string destinationPath, string sourcePath)
        {
            UploadFile(scpClient, destinationPath, new FileInfo(sourcePath));
        }
        public void UploadFile(string destinationPath, FileInfo fileInfo)
        {
            ClientExecute((cp) => UploadFile(cp, new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read), destinationPath));
        }
        public static void UploadFile(ScpClient scpClient, string destinationPath, FileInfo fileInfo)
        {
            using (var fs = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read))
            {
                UploadFile(scpClient,fs, destinationPath); 
            }
        }
        public void UploadFile(string destinationPath, Action<StreamWriter> action)
        {
            using (var ms = new MemoryStream())
            {
                using (StreamWriter sw = new StreamWriter(ms))
                {
                    action(sw);
                    sw.Flush();
                    ms.Seek(0, SeekOrigin.Begin);

                    ClientExecute((cp) => UploadFile(cp, ms, destinationPath));
                }
            }
        }
        public static void UploadFile(ScpClient scpClient, string destinationPath, Action<StreamWriter> action)
        {
            using (var ms = new MemoryStream())
            {
                using (StreamWriter sw = new StreamWriter(ms))
                {
                    action(sw);
                    sw.Flush();

                    ms.Seek(0, SeekOrigin.Begin);

                    UploadFile(scpClient, ms, destinationPath);
                }
            }
        }
        public static void UploadFile(ScpClient client, Stream stream, string destinationPath)
        {
            System.Diagnostics.Debug.WriteLine($"Upload to {destinationPath}");

            EnsureConnection(client, scp => scp.Upload(stream, destinationPath));
        }
        protected static void EnsureConnection<C>(C client, Action<C> action, IRemotePathTransformation transformation = null) where C : BaseClient
        {
            bool briefly = client.IsConnected == false;

            if (briefly) client.Connect();

            if (client is ScpClient scp)
            {
                scp.RemotePathTransformation = transformation ?? RemotePathTransformation.None;
            }
            else
            {
                if ((transformation is null) == false)
                {
                    throw new ArgumentException($"{typeof(C).Name} does not support remote path transformation.", nameof(transformation), new NotSupportedException(typeof(C).Name));
                }
            }

            action(client);

            if (briefly) client.Disconnect();
        }
        /// <summary>
        ///  used in SynoReportViaSSH
        /// </summary>
        /// <param name="client"></param>
        /// <param name="source"></param>
        /// <param name="localfile"></param>
        /// <param name="success"></param>
        public static void DownloadFile(ScpClient client, string source, FileInfo localfile, out bool success)
        {
            success = true;
            try
            {
                DownloadFile(client, source, localfile);
            }
            catch
            {
                success = false;
            }
        }
        public static void DownloadFile(ScpClient client, string source, FileInfo localfile)
        {
            System.Diagnostics.Debug.WriteLine($"Download from {source}");
            if (localfile.Exists == false)
            {
                EnsureConnection(client, scp => scp.Download(source, localfile));
            }
            else
            {
                throw new IOException("File already exists.", new ArgumentException(localfile.FullName));
            }
        }
        public void DownloadFile(string source, FileInfo localfile)
        {
            ClientExecute(scp => DownloadFile(scp, source, localfile));
        }
        public MemoryStream DownloadFile(string source)
        {
            DownloadFile(source, out MemoryStream stream);
            return stream;
        }

        /// <summary>
        /// Download a file;
        /// </summary>
        /// <param name="source"></param>
        /// <param name="stream"></param>
        public void DownloadFile(string source, out MemoryStream stream, IRemotePathTransformation transformation = null)
        {
            MemoryStream ms = null;
            ClientExecute(scp => EnsureConnection(scp, cp => ms = DownloadStream(cp, source), transformation));
            stream = ms;
        }
        private MemoryStream DownloadStream(ScpClient client, string source)
        {
            var result = new MemoryStream();

            client.Download(source, result);
            result.Seek(0, SeekOrigin.Begin);
            return result;
        }
        //public void DownloadFile(ScpClient client, string source, out MemoryStream stream)
        //{
        //    stream = DownloadStream(client, source);
        //}

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _ci.AuthenticationBanner -= AuthorizationBannerAction;

                    foreach (var am in _ci.AuthenticationMethods)
                    {
                        if (am is KeyboardInteractiveAuthenticationMethod kb)
                        {
                            kb.AuthenticationPrompt -= AuthenticationPromptAction;
                        }
                    }

                    HostKeyChange -= _hostKeyChange;
                }

                disposedValue = true;
            }
        }
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
