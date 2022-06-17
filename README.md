# Example C++ Response Signature Verification

This is an example of cryptographically verifying [response signatures](https://keygen.sh/docs/api/signatures/#response-signatures)
using your Keygen account's Ed25519 public key. Response signatures can help prevent replay
attacks, among other attack vectors, such as a man-in-the-middle attack. You can find your
public key within [your account's settings page](https://app.keygen.sh/settings).

All dependencies are under `include/`, except for libcurl.

## Running the example

First up, add an environment variable containing your public key:

```bash
# Your Keygen account's Ed25519 public key
export KEYGEN_PUBLIC_KEY="e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"

# Your Keygen account's ID
export KEYGEN_ACCOUNT="1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"

# An API token
export KEYGEN_TOKEN="activ-..."
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

On macOS, compile the source using `g++`:

```bash
g++ main.cpp -o bin.out -std=c++17 -stdlib=libc++ -lcurl -I include/**/*.c
```

Then run the script, passing in an API endpoint path:

```bash
./bin.out /me
```

Alternatively, you can prefix the below command with env variables, e.g.:

```bash
KEYGEN_PUBLIC_KEY=... KEYGEN_ACCOUNT=... KEYGEN_TOKEN=... ./bin.out /me
```

The response body's signature will be verified using Ed25519.

You can find your public key in [your settings](https://app.keygen.sh/settings).

## Running on other platforms

We are only including instructions on how to compile and run this example on
macOS. If you'd like to create a PR with instructions for another platform,
such as Windows or Linux, please feel free to open a PR.

If you have any tips on how to improve the compilation, please open a PR.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
