using System;
using System.Reflection;

namespace SenjataNLogHelper
{
    public static class NLogConfigHelper
    {
        // DJB2 hashes of NLog type FullNames. Computed by compute-nlog-hashes.py.
        // The original strings appear only in this comment; never in the compiled .exe.
        const uint H_LOG_MANAGER  = 0xD7DCE440; // "NLog.LogManager"
        const uint H_LOG_CONFIG   = 0xB5AFB026; // "NLog.Config.LoggingConfiguration"
        const uint H_CONSOLE_TGT  = 0x0F3F94A5; // "NLog.Targets.ConsoleTarget"
        const uint H_LOG_LEVEL    = 0xFFE6CC1D; // "NLog.LogLevel"

        public static void Main(string[] args)
        {
            try
            {
                ConfigureNLogIfPresent();
                RegisterAssemblyLoadEvent();
            }
            catch
            {
                // Silent — never crash the host process even if NLog reflection fails.
            }
        }

        static uint Djb2(string s)
        {
            uint h = 5381;
            for (int i = 0; i < s.Length; i++)
            {
                h = unchecked((h << 5) + h + (uint)s[i]);
            }
            return h;
        }

        static Type FindByHash(uint hash)
        {
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type[] types = null;
                try
                {
                    types = asm.GetTypes();
                }
                catch (ReflectionTypeLoadException ex)
                {
                    types = ex.Types;
                }
                catch
                {
                    continue;
                }
                if (types == null) continue;
                foreach (Type t in types)
                {
                    if (t == null) continue;
                    if (t.FullName == null) continue;
                    if (Djb2(t.FullName) == hash) return t;
                }
            }
            return null;
        }

        static void ConfigureNLogIfPresent()
        {
            Type logMgr  = FindByHash(H_LOG_MANAGER);
            Type cfgType = FindByHash(H_LOG_CONFIG);
            Type tgtType = FindByHash(H_CONSOLE_TGT);
            Type lvlType = FindByHash(H_LOG_LEVEL);
            if (logMgr == null || cfgType == null || tgtType == null || lvlType == null)
                return;

            object config = Activator.CreateInstance(cfgType);
            object target = Activator.CreateInstance(tgtType, new object[] { "c" });

            // Layout property intentionally not set — default layout is acceptable.

            FieldInfo infoField  = lvlType.GetField("Info",  BindingFlags.Static | BindingFlags.Public);
            FieldInfo fatalField = lvlType.GetField("Fatal", BindingFlags.Static | BindingFlags.Public);
            if (infoField == null || fatalField == null) return;
            object info  = infoField.GetValue(null);
            object fatal = fatalField.GetValue(null);

            Type targetBaseType = tgtType.BaseType;
            while (targetBaseType != null && targetBaseType.FullName != "NLog.Targets.Target")
            {
                targetBaseType = targetBaseType.BaseType;
            }

            MethodInfo addRule = cfgType.GetMethod("AddRule",
                new Type[] { lvlType, lvlType, targetBaseType ?? tgtType });
            if (addRule == null) return;
            addRule.Invoke(config, new object[] { info, fatal, target });

            PropertyInfo configProp = logMgr.GetProperty("Configuration",
                BindingFlags.Static | BindingFlags.Public);
            if (configProp == null) return;
            configProp.SetValue(null, config, null);
        }

        static void RegisterAssemblyLoadEvent()
        {
            AppDomain.CurrentDomain.AssemblyLoad += (sender, evtArgs) =>
            {
                try { ConfigureNLogIfPresent(); } catch { /* silent */ }
            };
        }
    }
}
