using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DiskStationManager.SecureShell
{
    internal class ScriptBuffer: IDisposable
    {
        private List<string> _buffer = new List<string>();
        private bool disposedValue;

        private ScriptBuffer() { }

        public static ScriptBuffer Create() => new ScriptBuffer();
        public static ScriptBuffer Create(params string[] lines)
        {
            var result = Create();
            foreach (var line in lines)
                result.Add(line);
            return result;
        }

        public ScriptBuffer Add(string line)
        {
            _buffer.Add(line);
            return this;
        }
        public void WriteToScript(StreamWriter sw, string magicToken = "#!/bin/bash")
        {
            sw.Write(magicToken);
            sw.Write("\n");
            foreach (var line in _buffer)
            {
                sw.Write(line);
                sw.Write("\n");
            }
        }
        public string[] GetContents() => _buffer.ToArray();

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _buffer.Clear();
                    _buffer = null;
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public static partial class Extensions
    {
        internal static ScriptBuffer Remove(this ScriptBuffer @this, string fileSpec) => @this.Add(BConsoleCommand.RemoveFileCommand(fileSpec));
        internal static ScriptBuffer Remove(this ScriptBuffer @this, string rootPath, ConsoleFileInfo file) => @this.Add(BConsoleCommand.RemoveFileCommand(rootPath, file));
        internal static ScriptBuffer CreateDirectory(this ScriptBuffer @this, string folderName) => @this.Add($"mkdir {folderName}");
        internal static ScriptBuffer ChangeDirectory(this ScriptBuffer @this, string folderName) => @this.Add($"cd {folderName}");
        internal static ScriptBuffer ChangeToHomeDirectory(this ScriptBuffer @this) => @this.Add($"cd ~");
        internal static ScriptBuffer ChangeOwner(this ScriptBuffer @this, string folderName, string userName, bool recursive = false) => @this.Add($"chown{(recursive ? " -R" : string.Empty)} {userName} {folderName}");
        internal static ScriptBuffer ChangeFileMode(this ScriptBuffer @this, string fileSpec, string mode, bool recursive = false) => @this.Add($"chmod{(recursive ? " -R" : string.Empty)} {mode} {fileSpec}");
        internal static ScriptBuffer Copy(this ScriptBuffer @this, string source, string destination) => @this.Add($"cp {source} {destination}");
        internal static ScriptBuffer CopyFileAndChangeFileMode(this ScriptBuffer @this, string source, string destination, string fileMode) => @this
                .Copy(source, destination)
                .ChangeFileMode(destination, fileMode);
    }
}
