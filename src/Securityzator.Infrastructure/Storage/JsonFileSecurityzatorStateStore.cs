using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Securityzator.Infrastructure.Pathing;

namespace Securityzator.Infrastructure.Storage;

public sealed class JsonFileSecurityzatorStateStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
    private readonly string _dataFilePath;
    private readonly string _mutexName;

    public JsonFileSecurityzatorStateStore(
        IOptions<SecurityzatorStorageOptions> options,
        IHostEnvironment hostEnvironment)
    {
        var configuredPath = string.IsNullOrWhiteSpace(options.Value.DataFilePath)
            ? "App_Data/securityzator-state.json"
            : options.Value.DataFilePath.Trim();

        _dataFilePath = SecurityzatorPathResolver.ResolveFilePath(
            configuredPath,
            hostEnvironment.ContentRootPath);

        _mutexName = string.IsNullOrWhiteSpace(options.Value.MutexName)
            ? "Local\\Securityzator.StateStore"
            : options.Value.MutexName.Trim();
    }

    public async Task<TResult> ReadAsync<TResult>(
        Func<SecurityzatorStateDocument, TResult> reader,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            using var mutex = AcquireProcessGate(cancellationToken);
            var state = LoadUnsafe();
            return reader(state);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<TResult> WriteAsync<TResult>(
        Func<SecurityzatorStateDocument, TResult> writer,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);

        try
        {
            using var mutex = AcquireProcessGate(cancellationToken);
            var state = LoadUnsafe();
            var result = writer(state);
            SaveUnsafe(state);
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    private SecurityzatorStateDocument LoadUnsafe()
    {
        if (!File.Exists(_dataFilePath))
        {
            return new SecurityzatorStateDocument();
        }

        using var stream = File.OpenRead(_dataFilePath);
        return JsonSerializer.Deserialize<SecurityzatorStateDocument>(stream, _serializerOptions)
               ?? new SecurityzatorStateDocument();
    }

    private void SaveUnsafe(SecurityzatorStateDocument state)
    {
        var directory = Path.GetDirectoryName(_dataFilePath);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var stream = File.Create(_dataFilePath);
        JsonSerializer.Serialize(stream, state, _serializerOptions);
    }

    private ProcessMutexLease AcquireProcessGate(CancellationToken cancellationToken)
    {
        var mutex = new Mutex(false, _mutexName);
        var acquired = false;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    acquired = mutex.WaitOne(TimeSpan.FromMilliseconds(250));
                }
                catch (AbandonedMutexException)
                {
                    acquired = true;
                }

                if (acquired)
                {
                    return new ProcessMutexLease(mutex, acquired: true);
                }
            }
        }
        catch
        {
            mutex.Dispose();
            throw;
        }

        mutex.Dispose();
        throw new OperationCanceledException(cancellationToken);
    }

    private sealed class ProcessMutexLease : IDisposable
    {
        private readonly Mutex _mutex;
        private readonly bool _acquired;
        private bool _disposed;

        public ProcessMutexLease(Mutex mutex, bool acquired)
        {
            _mutex = mutex;
            _acquired = acquired;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            if (_acquired)
            {
                _mutex.ReleaseMutex();
            }

            _mutex.Dispose();
            _disposed = true;
        }
    }
}
