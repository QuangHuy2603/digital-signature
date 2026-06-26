export function parseCliArgs(argv = process.argv.slice(2)) {
    const result = {};
    for (let index = 0; index < argv.length; index += 1) {
        const token = argv[index];
        if (!token.startsWith("--")) continue;

        const key = token.slice(2);
        const next = argv[index + 1];
        if (!next || next.startsWith("--")) {
            result[key] = true;
            continue;
        }

        result[key] = next;
        index += 1;
    }
    return result;
}

export function requireArg(args, name) {
    const value = args[name];
    if (value === undefined || value === null || value === "") {
        throw new Error(`Missing required argument --${name}`);
    }
    return value;
}
