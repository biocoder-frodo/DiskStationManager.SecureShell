using System.Collections.Generic;

namespace DiskStationManager.SecureShell
{
    public sealed class DSMVersion6 : BDSMVersion
    {
        public DSMVersion6(Dictionary<string, string> properties)
            : base(properties)
        {
        }

        public string ProductVersion { get { return _props["productversion"]; } }
        public override string Version { get { return $"DSM {ProductVersion}-{BuildNumber}" + (PatchVersion > 0 ? $" Update {PatchVersion}" : ""); } }
    }
}
