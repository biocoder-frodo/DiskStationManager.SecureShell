
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using static System.Security.Cryptography.DpApiString;

namespace System.Security.Cryptography
{
    public class WrappedPassword<T>
        where T : class
    {
        private readonly PropertyInfo _property;
        private readonly T _instance;
        private static byte[] vector = null;
        private static readonly object vectorlock = new object();
        private static DataProtectionScope scope = DataProtectionScope.CurrentUser;
        public WrappedPassword(string propname, T instance)
        {
            lock (vectorlock)
            {
                if (vector == null)
                {
                    vector = Encoding.Unicode.GetBytes("Is a gift a gift without wrapping?");
                }
            }
            _instance = instance;
            _property = _instance.GetType().GetProperty(propname, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
        }
        public T Value { get { return _instance; } }
        public string Password
        {
            get
            {
                return ToInsecureString(DecryptString((string)_property.GetValue(_instance), scope, vector));
            }
            set
            {
                _property.SetValue(_instance, EncryptString(ToSecureString(value), scope, vector));
            }
        }
        public static void SetEntropy(string data, DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            lock (vectorlock)
            {
                vector = Encoding.Unicode.GetBytes(data);
            }
        }
    }


    public static class DpApiString
    {

        public static string EncryptString(SecureString input, DataProtectionScope scope, byte[] entropy)
        {
            return Convert.ToBase64String(ProtectedData.Protect(Encoding.Unicode.GetBytes(ToInsecureString(input)), entropy, scope));
        }

        public static SecureString DecryptString(string encryptedData, DataProtectionScope scope, byte[] entropy)
        {
            try
            {
                return ToSecureString(Encoding.Unicode.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encryptedData), entropy, scope)));
            }
            catch
            {
                return new SecureString();
            }
        }

        internal static SecureString ToSecureString(string input)
        {
            SecureString result = new SecureString();
            foreach (char c in input)
            {
                result.AppendChar(c);
            }
            result.MakeReadOnly();
            return result;
        }

        public static string ToInsecureString(SecureString input)
        {
            string result = string.Empty;
            IntPtr ptr = Marshal.SecureStringToBSTR(input);
            try
            {
                result = Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                Marshal.ZeroFreeBSTR(ptr);
            }
            return result;
        }

        public static string StringFromConsole()
        {
            var sb = SensitiveInfoFromConsole(() => new StringBuilder(), s => s.Length, (s, k) => s.Append(k), s => s.Remove(s.Length - 1, 1));
            return sb.ToString();
        }
        public static SecureString SecureStringFromConsole()
        {
            var pass = SensitiveInfoFromConsole(() => new SecureString(), s => s.Length, (s, k) => s.AppendChar(k), s => s.RemoveAt(s.Length - 1));
            pass.MakeReadOnly();
            return pass;
        }

        private static P SensitiveInfoFromConsole<P>(Func<P> ctor, Func<P, int> length, Action<P, char> keyAction, Action<P> backspaceAction, char passwordChar = '*') where P : class
        {
            var info = ctor();
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && length(info) > 0)
                {
                    Console.Write("\b \b");

                    backspaceAction(info);
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write(passwordChar);
                    keyAction(info, keyInfo.KeyChar);
                }
            } while (key != ConsoleKey.Enter);
            Console.WriteLine();
            return info;
        }



    }

}

