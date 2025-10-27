import {
    DigestAlgorithmEnum,
    PrivateKeyTypeEnum,
    SAMLBindingsEnum,
    SignatureAlgorithmEnum,
} from "@goauthentik/api";

import { msg } from "@lit/localize";

type Option<T> = [string, T, boolean?];

function toOptions<T>(options: Option<T>[]) {
    return options.map(([label, value, isDefault]: Option<T>) => ({
        label,
        value,
        default: isDefault ?? false,
    }));
}

export const spBindingOptions = toOptions([
    [msg("Redirect"), SAMLBindingsEnum.Redirect, true],
    [msg("Post"), SAMLBindingsEnum.Post],
]);

export const digestAlgorithmOptions = toOptions([
    ["SHA1", DigestAlgorithmEnum.HttpWwwW3Org200009Xmldsigsha1],
    ["SHA256", DigestAlgorithmEnum.HttpWwwW3Org200104Xmlencsha256, true],
    ["SHA384", DigestAlgorithmEnum.HttpWwwW3Org200104XmldsigMoresha384],
    ["SHA512", DigestAlgorithmEnum.HttpWwwW3Org200104Xmlencsha512],
]);

export const signatureAlgorithmShas = toOptions([
    ["SHA1", "sha1"],
    ["SHA256", "sha256", true],
    ["SHA384", "sha384"],
    ["SHA512", "sha512"],
]);

export type CryptoHashKind = "SHA1" | "SHA256" | "SHA384" | "SHA512";

export const availableHashes: CryptoHashKind[] = ["SHA1", "SHA256", "SHA384", "SHA512"];

export const SignatureFamilyByHashAlgorithm: Partial<
    Record<PrivateKeyTypeEnum, ReadonlyMap<CryptoHashKind, SignatureAlgorithmEnum>>
> = {
    [PrivateKeyTypeEnum.Rsa]: new Map([
        ["SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200009XmldsigrsaSha1],
        ["SHA256", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha256],
        ["SHA384", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha384],
        ["SHA512", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha512],
    ]),
    [PrivateKeyTypeEnum.Ec]: new Map([
        ["SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha1],
        ["SHA256", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha256],
        ["SHA384", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha384],
        ["SHA512", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha512],
    ]),
    [PrivateKeyTypeEnum.Dsa]: new Map([
        ["SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200009XmldsigdsaSha1],
    ]),
};

export function retrieveSignatureAlgorithm(
    family: PrivateKeyTypeEnum,
    digest: CryptoHashKind,
): SignatureAlgorithmEnum | null {
    const familyMap = SignatureFamilyByHashAlgorithm[family];
    if (!familyMap) return null;

    return familyMap.get(digest) ?? null;
}

export const signatureAlgorithmOptions = toOptions([
    ["RSA-SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200009XmldsigrsaSha1],
    ["RSA-SHA256", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha256, true],
    ["RSA-SHA384", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha384],
    ["RSA-SHA512", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMorersaSha512],
    ["ECDSA-SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha1],
    ["ECDSA-SHA256", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha256],
    ["ECDSA-SHA384", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha384],
    ["ECDSA-SHA512", SignatureAlgorithmEnum.HttpWwwW3Org200104XmldsigMoreecdsaSha512],
    ["DSA-SHA1", SignatureAlgorithmEnum.HttpWwwW3Org200009XmldsigdsaSha1],
]);
