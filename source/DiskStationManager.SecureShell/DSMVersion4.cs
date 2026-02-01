using System.Collections.Generic;

namespace DiskStationManager.SecureShell
{
    public sealed class DSMVersion4 : BDSMVersion
    {
        public DSMVersion4(Dictionary<string, string> properties)
            : base(properties)
        {
        }
        public override string Version { get { return $"DSM {MajorVersion}.{MinorVersion}-{BuildNumber}" + (PatchVersion > 0 ? $" Update {PatchVersion}" : ""); } }

    }
}
