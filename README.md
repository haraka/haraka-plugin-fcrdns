[![Build Status][ci-img]][ci-url]
[![Code Climate][clim-img]][clim-url]
[![Greenkeeper badge][gk-img]][gk-url]
[![NPM][npm-img]][npm-url]
<!-- requires URL update [![Windows Build Status][ci-win-img]][ci-win-url] -->
<!-- doesn't work in haraka plugins... yet. [![Code Coverage][cov-img]][cov-url]-->

# haraka-plugin-template

Clone me, to create a new plugin!

After following the instructions, remove them and put your content here.


# Instructions

These instructions will not self-destruct after use.

See also, [How to Write a Plugin](https://github.com/haraka/Haraka/wiki/Write-a-Plugin) and [Plugins.md](https://github.com/haraka/Haraka/blob/master/docs/Plugins.md) for additional plugin writing information.

## Create a new repo for your plugin

Haraka plugins are named like `haraka-plugin-something`. All the namespace
after `haraka-plugin-` is yours for the taking. Please check the [Plugins]() page and a Google search to see what plugins already exist.

Once you've settled on a name, create the GitHub repo. On the repo's main page, click the _Clone or download_ button and copy the URL. Then paste that URL into a local ENV variable with a command like this:

```sh
export MY_PLUGIN_NAME=haraka-plugin-SOMETHING
export MY_PLUGIN_REPO=git@github.com:SOME_ORG/haraka-plugin-SOMETHING.git
```

Clone and rename the template repo:

```sh
git clone git@github.com:haraka/haraka-plugin-template.git
mv haraka-plugin-template $MY_PLUGIN_REPO
cd $MY_PLUGIN_REPO
git remote rm origin
git remote add origin $MY_PLUGIN_REPO
```

Now you'll have a local git repo to begin authoring your plugin

## rename boilerplate

Replaces all uses of the word `template` with your plugin's name.

git push


# Enable Travis-CI testing

- [ ] visit your [Travis-CI profile page](https://travis-ci.org/profile) and enable Continuous Integration testing on the repo
- [ ] enable Code Climate. Click the _code climate_ badge and import your repo



# Insert your content here



<!-- leave these buried at the bottom of the document -->
[ci-img]: https://travis-ci.org/haraka/haraka-plugin-template.svg
[ci-url]: https://travis-ci.org/haraka/haraka-plugin-template
[ci-win-img]: https://ci.appveyor.com/api/projects/status/CHANGETHIS?svg=true
[ci-win-url]: https://ci.appveyor.com/project/haraka/haraka-CHANGETHIS
[cov-img]: https://codecov.io/github/haraka/haraka-plugin-template/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-plugin-template
[clim-img]: https://codeclimate.com/github/haraka/haraka-plugin-template/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-plugin-template
[gk-img]: https://badges.greenkeeper.io/haraka/haraka-plugin-template.svg
[gk-url]: https://greenkeeper.io/
[npm-img]: https://nodei.co/npm/haraka-plugin-template.png
[npm-url]: https://www.npmjs.com/package/haraka-plugin-template
