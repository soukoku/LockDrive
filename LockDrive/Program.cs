using LockDrive.Resources;
using System;
using System.Diagnostics;
using System.Globalization;
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
            if (IsSupportedOS())
            {
                var maybeDrive = (args.FirstOrDefault() ?? PromptForDrive()).Trim();

                if (!string.IsNullOrEmpty(maybeDrive) &&
                    CheckOrRestartAsAdmin(maybeDrive))
                {
                    if (maybeDrive.Length == 1)
                    {
                        maybeDrive += ':';
                    }
                    try
                    {
                        // trim extra " as a workaround for bug in command line parameter parsing 
                        // (seen by dragging drive icon to exe as parameter)
                        var drive = new DirectoryInfo(maybeDrive.Trim('\"'));
                        if (drive.Parent == null)
                        {
                            Console.WriteLine(Texts.WorkingLine);
                            LockDrive(drive.Name);
                            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, Texts.SuccessLineFormat, drive.Name));
                        }
                        else
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, Texts.ErrorNotDriveFormat, maybeDrive));
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, Texts.ErrorLineFormat, ex.Message));
                        Console.WriteLine();
                        Console.WriteLine(Texts.ExitLine);
                        Console.ReadLine();
                    }
                }
            }
            else
            {
                Console.WriteLine(Texts.ErrorNotSupportedOS);
            }
        }

        private static bool IsSupportedOS()
        {
            // only vista or higher
            return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                Environment.OSVersion.Version >= new Version(6, 0);
        }

        private static string PromptForDrive()
        {
            Console.WriteLine(Texts.PromptBanner);
            Console.WriteLine();
            Console.Write(Texts.PromptLine);
            return Console.ReadLine();
        }

        private static void LockDrive(string drive)
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
                    if (drive.StartsWith(letter, StringComparison.OrdinalIgnoreCase))
                    {
                        var status = (uint)vol["ProtectionStatus"];
                        if (status == 1)
                        {
                            using (var inParams = vol.GetMethodParameters("Lock"))
                            {
                                inParams["ForceDismount"] = false;
                                using (var outParams = vol.InvokeMethod("Lock", inParams, null))
                                {
                                    var result = (uint)outParams["returnValue"];
                                    switch (result)
                                    {
                                        case 0://S_OK
                                            return;
                                        case 0x80070005: // E_ACCESS_DENIED
                                            throw new InvalidOperationException(Texts.ErrorAccessDenied);
                                        case 0x80310001: // FVE_E_NOT_ENCRYPTED
                                            throw new InvalidOperationException(Texts.ErrorNotEncrypted);
                                        case 0x80310021: // FVE_E_PROTECTION_DISABLED
                                            throw new InvalidOperationException(Texts.ErrorProtectionDisabled);
                                        case 0x80310022: // FVE_E_RECOVERY_KEY_REQUIRED
                                            throw new InvalidOperationException(Texts.ErrorKeyRequired);
                                        default:
                                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, Texts.ErrorUnknownCodeFormat, result));
                                    }
                                }
                            }
                        }
                        else
                        {
                            throw new InvalidOperationException(Texts.ErrorNotUBLDrive);
                        }
                    }
                }
            }
            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, Texts.ErrorNoMatchingDriveFormat, drive));
        }

        private static bool CheckOrRestartAsAdmin(string arg)
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