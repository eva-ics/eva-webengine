all:
	npm run build

bump:
	npm version --no-git-tag-version patch
	sed -i "s/\(const eva_webengine_version\).*/\1 = \"`jq < package.json -r .version`\";/g" ./src/lib.ts

pub:
	rci x eva.webengine
