# How to create new posts

Make sure you have installed `hugo` (https://gohugo.io/getting-started/installing/). `hugo` must be run from the root directory of this repository (e.g. `/home/user/path/to/lolcads.github.io/`). Make also sure that everything renders just fine:

```
$ hugo server
```

Choose a title/filename (without spaces or any other strange character), for example, "awesome_new_post":

```bash
$ ./new_post.sh awesome_new_post
/home/user/path/to/lolcads.github.io/content/posts/2022/02/awesome_new_post.md created
info: you can use static/2022/02 for images
```

The new file looks like:

```markdown
---
title: "Awesome_new_post"
date: 2022-02-22T15:35:21+01:00
draft: true
---
```

You finally should change `draft: true` to `draft: false` and adjust the title to something prettier, like "Awesome new post". If you want to leave it as a draft for now, make sure you use `hugo server -D` to also render drafts.

For images you can use the provided subdirectory under `static/<year>/<month>` and insert them with Markdown like this:

```markdown
![...alt text here...](/<year>/<month>/image.png)
```

or more concrete:

```markdown
![AFL++ output screen](/2022/02/afl.svg)
```

After you pushed you changes to GitHub the site will be rendered automatically with a GitHub Action (more info here: https://gohugo.io/hosting-and-deployment/hosting-on-github/ and https://github.com/peaceiris/actions-hugo)

Check out the existing pages under `content/` for additional settings (table of contents, tags, ...) or `themes/terminal/archetypes/posts.md`.