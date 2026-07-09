# frozen_string_literal: true

require "bcrypt"

# Hash a password with a fresh random salt. cost: is the work factor
# (higher = slower = stronger); it defaults to BCrypt::Engine::DEFAULT_COST.
password = BCrypt::Password.create("super secret", cost: 4)
puts password.version  # => 2a
puts password.cost     # => 4

# The Password is a "$2a$NN$...." String; verify a candidate in constant time.
puts(password == "super secret") # => true
puts(password == "wrong")        # => false
puts password.is_password?("super secret") # => true

# Re-parse a stored hash and verify against it — this is the login path.
stored = password.to_s
puts(BCrypt::Password.new(stored) == "super secret") # => true

# Low-level Engine surface: build a salt, then hash a secret under it.
salt = BCrypt::Engine.generate_salt(4)     # => "$2a$04$...."
hash = BCrypt::Engine.hash_secret("super secret", salt)
puts BCrypt::Engine.autodetect_cost(hash)  # => 4
puts BCrypt::Engine.valid_secret?("super secret") # => true
