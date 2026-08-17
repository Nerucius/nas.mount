using LiteDB;
using System.Security.Cryptography;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: LiteDbProbe <database-path>");
    return 2;
}

string databasePath = Path.GetFullPath(args[0]);
Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
byte[] payload = new byte[32 * 1024];
RandomNumberGenerator.Fill(payload);

try
{
    using (LiteDatabase database = new(databasePath))
    {
        ILiteCollection<BsonDocument> records =
            database.GetCollection("checkpoint_probe");
        records.EnsureIndex("cycle");

        for (int i = 0; i < 1500; i++)
        {
            BsonDocument document = new()
            {
                ["_id"] = i % 400,
                ["cycle"] = i,
                ["payload"] = payload,
            };
            records.Upsert(document);

            if (i % 25 == 0)
            {
                BsonDocument found = records.FindById(i % 400);
                if (found is null || found["cycle"].AsInt32 != i)
                {
                    throw new InvalidDataException(
                        $"record {i % 400} did not round-trip at cycle {i}");
                }
            }

            if (i > 0 && i % 250 == 0)
            {
                Console.WriteLine($"checkpoint workload: {i}/1500 upserts");
            }
        }

        database.Checkpoint();
        if (records.Count() != 400)
        {
            throw new InvalidDataException(
                $"expected 400 final records, found {records.Count()}");
        }
    }

    using (LiteDatabase reopened = new(new ConnectionString
    {
        Filename = databasePath,
        ReadOnly = true,
    }))
    {
        long count = reopened.GetCollection("checkpoint_probe").Count();
        if (count != 400)
        {
            throw new InvalidDataException(
                $"reopened database expected 400 records, found {count}");
        }
    }

    Console.WriteLine("PASS: LiteDB checkpoint, query, close, and reopen workload");
    return 0;
}
finally
{
    try { File.Delete(databasePath); } catch { }
    try { File.Delete(Path.ChangeExtension(databasePath, "-log.ldb")); } catch { }
    try
    {
        string directory = Path.GetDirectoryName(databasePath);
        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory);
        }
    }
    catch { }
}
