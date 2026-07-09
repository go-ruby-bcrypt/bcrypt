# Examples

Runnable pure-Ruby usage of the `bcrypt` password-hashing surface, verified under the [rbgo](https://github.com/go-embedded-ruby/ruby) interpreter.

```sh
rbgo examples/bcrypt_usage.rb
```

| File | Shows |
| --- | --- |
| `bcrypt_usage.rb` | `BCrypt::Password.create`/`.new`, `#==`/`#is_password?`, `#cost`/`#version`/`#to_s`, and `BCrypt::Engine.generate_salt`/`hash_secret`/`autodetect_cost`/`valid_secret?` |
