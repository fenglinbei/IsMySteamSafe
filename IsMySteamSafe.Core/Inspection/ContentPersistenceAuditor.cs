using Microsoft.Win32;
using System.Xml;
using System.Xml.Linq;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.Core.Inspection;

public static class ContentPersistenceAuditor
{
    public static void Observe(IReadOnlyDictionary<string, string> knownFiles, AuditReport report, CancellationToken token)
    {
        void Match(string name, string command)
        {
            foreach (string path in CommandTargets.Extract(command))
                if (knownFiles.TryGetValue(path, out string? hash))
                    report.Findings.Add(new AuditFinding { Id = "CONTENT.PERSISTENCE." + name, Area = AuditArea.Persistence,
                        Level = AuditLevel.HighlySuspicious, Priority = AuditPriority.P1, EvidenceState = "persistence-present",
                        Title = "启动链指向已知恶意文件", WhatFound = name, Target = path,
                        Meaning = "已记录的启动命令与本机恶意文件相符，说明存在启动入口，不证明这次已执行。",
                        Recommendation = "使用 SteamSentinel 或专业杀毒软件检查并处理该入口，重启后再次检查。",
                        Evidence = [new("SHA-256", hash), new("启动入口", name)] });
        }
        try
        {
            foreach (var (hive, view) in new[] { (RegistryHive.CurrentUser, RegistryView.Default), (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32) })
            foreach (string subkey in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                using RegistryKey root = RegistryKey.OpenBaseKey(hive, view); using RegistryKey? key = root.OpenSubKey(subkey);
                if (key is null) continue;
                foreach (string name in key.GetValueNames().Take(1024))
                { token.ThrowIfCancellationRequested(); Match(hive + "/" + view + "/" + subkey + "/" + name, key.GetValue(name)?.ToString() ?? ""); }
            }
            using RegistryKey? services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is not null)
                foreach (string name in services.GetSubKeyNames().Take(4096))
                {
                    token.ThrowIfCancellationRequested(); using RegistryKey? service = services.OpenSubKey(name);
                    Match("服务/" + name, service?.GetValue("ImagePath")?.ToString() ?? "");
                }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { report.CoverageNotes.Add("部分内容关联启动项无法读取。"); }
        List<string> notes = [];
        string tasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        foreach (string path in ContentDiscovery.Files(tasks, notes, 4096, 8, token))
        {
            try
            {
                if (new FileInfo(path).Length > 1024 * 1024) { notes.Add("任务文件超过读取上限：" + path); continue; }
                using XmlReader reader = XmlReader.Create(path, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
                XDocument document = XDocument.Load(reader);
                foreach (XElement exec in document.Descendants().Where(e => e.Name.LocalName == "Exec"))
                    Match("任务/" + Path.GetRelativePath(tasks, path), string.Join(" ", exec.Elements().Where(e => e.Name.LocalName is "Command" or "Arguments").Select(e => e.Value)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException)
            { notes.Add("任务无法完整读取：" + path); }
        }
        report.CoverageNotes.AddRange(notes);
    }
}
