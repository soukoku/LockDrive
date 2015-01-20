using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Principal;

namespace LockDrive
{
    class Program
    {
        static void Main(string[] args)
        {
            var maybeDrive = args.FirstOrDefault();
            if (string.IsNullOrEmpty(maybeDrive))
            {
                Console.WriteLine("==================================================");
                Console.WriteLine("This utility locks an unlocked BitLocker drive.");
                Console.WriteLine("Pass the drive letter as the parameter or type it");
                Console.WriteLine("below to use it.");
                Console.WriteLine("==================================================");
                Console.WriteLine();
                Console.Write("Enter the drive letter (or enter to exit):");

                maybeDrive = Console.ReadLine();
            }

            if (!string.IsNullOrEmpty(maybeDrive) &&
                CheckAndRestartAsAdmin(maybeDrive))
            {
                if (maybeDrive.Length == 1)
                {
                    maybeDrive += ':';
                }
                try
                {
                    var drive = new DirectoryInfo(maybeDrive.Trim(' ', '\"'));
                    if (drive.Parent == null)
                    {
                        TryUnUnlockDrive(drive);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                    Console.WriteLine();
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadLine();
                }
            }
        }

        private static void TryUnUnlockDrive(DirectoryInfo drive)
        {
            var path = new ManagementPath
            {
                NamespacePath = "\\ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
                ClassName = "Win32_EncryptableVolume"
            };

            using (var wmiClass = new ManagementClass(path))
            {
                foreach (ManagementObject vol in wmiClass.GetInstances())
                {
                    var letter = vol["DriveLetter"].ToString();
                    if (drive.Name.StartsWith(letter, StringComparison.OrdinalIgnoreCase))
                    {
                        var status = (uint)vol["ProtectionStatus"];
                        if (status == 1)
                        {
                            var inParams = vol.GetMethodParameters("Lock");
                            inParams["ForceDismount"] = false;
                            var outParams = vol.InvokeMethod("Lock", inParams, null);
                            var result = (uint)outParams["returnValue"];
                            switch (result)
                            {
                                case 0://S_OK
                                    return;
                                case 0x80070005: // E_ACCESS_DENIED
                                    throw new Exception("Access denied.");
                                case 0x80310001: // FVE_E_NOT_ENCRYPTED
                                    throw new Exception("Not encrypted.");
                                case 0x80310021: // FVE_E_PROTECTION_DISABLED
                                    throw new Exception("Protection disabled.");
                                case 0x80310022: // FVE_E_RECOVERY_KEY_REQUIRED
                                    throw new Exception("Key required.");
                                default:
                                    throw new Exception(string.Format("Unknown code {0:X}", result));
                            }
                        }
                        else
                        {
                            throw new Exception("Not an unlocked BitLocker drive.");
                        }
                    }
                }
            }
            throw new Exception(string.Format("No drive found for {0}.", drive.Name));
        }

        private static bool CheckAndRestartAsAdmin(string arg)
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }
            else
            {
                var startInfo = new ProcessStartInfo(Assembly.GetEntryAssembly().Location);
                startInfo.Arguments = arg;
                startInfo.Verb = "runas";
                Process.Start(startInfo);
            }
            return false;
        }
    }
}