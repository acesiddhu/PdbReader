using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.TeamFoundation.Build.Workflow;

namespace ConsoleApp22
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args == null || args.Count() <= 1)
            {
                Console.WriteLine("Usage: GetSourceFilesFromPdb <FolderToSearchForPdbs> <outputfile>");
            }

            string folder = args[0];
            StringBuilder builder = new StringBuilder();

            Stopwatch watch = Stopwatch.StartNew();

            using (var nm = new DbgHelpWrapper())
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.pdb", SearchOption.AllDirectories))
                {
                    var srcfiles = nm.GetIndexedSources(file);

                    Console.WriteLine(file);
                    builder.AppendLine(file);
                    foreach (var source in srcfiles)
                    {
                        builder.AppendLine("      " + source);
                    }
                }
            }

            Console.WriteLine("Took " + watch.ElapsedMilliseconds + "(ms)");

            File.WriteAllText(args[1], builder.ToString());
        }
    }
}
