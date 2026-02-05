Zork Network Node integration/staging tree
======================================

```
           __   ___       ___       __   __         ___      ___ 
| |\ |    |  \ |__  \  / |__  |    /  \ |__)  |\/| |__  |\ |  |  
| | \|    |__/ |___  \/  |___ |___ \__/ |     |  | |___ | \|  |  
```

https://zorkcoin.com

What is Zorkcoin?
-----------------

Zorkcoin is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Zorkcoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Zork Network Node is the name of open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Zork Network Node software, see the [releases](https://github.com/ZorkNetwork/zorkcoin/releases).

```text
+---------+
| Bitcoin | ->Scrypt
+---------+     ↓
           +----------+
           | Litecoin | ->kHeavyHash
           +----------+       ↓
                         +----------+
                         | Zorkcoin |
                         +----------+
```

### The Barbazzo Fernap Pseudonym

I know a number of you already know me, you know who you are, so you don't count. For others when you determine
my real name shoot me an email at barbazzo.fernap@zork.network and let me know you've figured it out! And HOW...
It's not a Satoshi level secret, and wasn't ever intended to be since people are more comfortable with Real names now.
I've never really intended on it being a 'secret' that I'd keep past my last workday, even though I'll probably
keep the pseudonym for this project even when my real name is common knowledge to everyone. At this point I'm
curious as to the ways people figure out such things?  And little puzzles are a common theme in the world of Zork!

License
-------

Zork Network Node is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `zorkcoin` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Release versions](https://github.com/ZorkNetwork/zorkcoin/releases) are created
regularly from release branches to indicate new official, stable release versions of Zork Network Node.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

The developer channel in [discord](http://discord.com/gmpSzpqCDh)
should be used to discuss complicated or controversial changes before working
on a patch set.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

We only accept translation fixes that are submitted through [Bitcoin Core's Transifex page](https://explore.transifex.com/bitcoin/bitcoin/).
Translations are converted to Litecoin periodically.

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
