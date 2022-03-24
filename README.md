# [to.dt.in.th](https://to.dt.in.th)

A web application that lets users send an encrypted message to [@dtinth](https://github.com/dtinth).

[<img width="839" alt="image" src="https://user-images.githubusercontent.com/193136/159846649-ab8a27fe-2b5d-4607-a606-c7f3e7845418.png">](https://to.dt.in.th)

## Why?

Sometimes people send me passwords over instant messaging apps or email. To make things a little bit more secure, I need a short URL that I can send people to where they can encrypt a message in a way that only I can decrypt it.

## How it works

A [TweetNaCl.js box](https://tweetnacl.js.org/#/box) is used to encrypt a message with a randomized public key and nonce. The resulting binary is then encoded using the [Braille Patterns Unicode block](https://en.wikipedia.org/wiki/Braille_Patterns). All source code is not minified and included within the repo (except the stylesheets).
