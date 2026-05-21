using System;
using System.IO;

class FlushHelper {
    static void Main(string[] args) {
        try {
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        } catch {}
    }
}
