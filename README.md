# [to.dt.in.th](https://to.dt.in.th)

A web application that lets users send an encrypted message to [@dtinth](https://github.com/dtinth).

[<img width="834" alt="image" src="https://user-images.githubusercontent.com/193136/159828360-b1848ccc-9149-4358-a651-402829f078ca.png">](https://to.dt.in.th)

## How it works

A [TweetNaCl.js box](https://tweetnacl.js.org/#/box) is used to encrypt a message with a randomized public key and nonce. The result is then converted to hex with a defined symbol set. All source code is not minified and included within the repo (except the stylesheets).
