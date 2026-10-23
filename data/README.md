# Example key

`parc_example_key` is a **deliberately public, throwaway** SSH key. It protects nothing and
must never be used for anything real. It exists so anyone can decrypt the sample files in this directory:

```sh
parc inspect --key data/parc_example_key data/<file>.parc
parc dec --key data/parc_example_key -o out data/<file>.parc
parc inspect --key data/parc_example_key https://github.com/sipak-gh/parc/raw/master/data/<file>.parc
```
