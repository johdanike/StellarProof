import { StatusCodes } from "http-status-codes";
import { SPVModel } from "../models/spv.model";
import ManifestModel, { IManifest } from "../models/Manifest.model";
import { AppError } from "../errors/AppError";
import type {
  IManifestEntry,
  ListManifestsQuery,
  ManifestListResult,
} from "../types/manifest.types";

const EXCLUDED_FIELDS = { encryptedPayload: 0 } as const;

class ManifestService {
  /**
   * Returns a paginated list of manifests owned by the given Stellar public key.
   */
  public async listManifests(query: ListManifestsQuery): Promise<ManifestListResult> {
    const { ownerPublicKey, limit, skip } = query;

    if (limit < 1 || limit > 100) {
      throw new AppError("limit must be between 1 and 100", StatusCodes.BAD_REQUEST, "INVALID_PAGINATION");
    }

    if (skip < 0) {
      throw new AppError("skip must be a non-negative integer", StatusCodes.BAD_REQUEST, "INVALID_PAGINATION");
    }

    const filter = { ownerPublicKey };

    const [manifests, total] = await Promise.all([
      SPVModel.find(filter, EXCLUDED_FIELDS)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean<IManifestEntry[]>(),
      SPVModel.countDocuments(filter),
    ]);

    return { manifests, total, limit, skip };
  }

  /**
   * Recursively sanitizes dynamic objects.
   * - Strips HTML/XML tags to prevent XSS.
   * - Truncates strings to 1000 characters to prevent DB bloat.
   */
  private sanitizePayload(val: unknown): unknown {
    if (typeof val === 'string') {
      const sanitized = val.replace(/<[^>]*>?/gm, '');
      return sanitized.substring(0, 1000);
    }
    if (Array.isArray(val)) {
      return val.map((item) => this.sanitizePayload(item));
    }
    if (val !== null && typeof val === 'object') {
      const sanitizedObj: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(val)) {
        sanitizedObj[key] = this.sanitizePayload(value);
      }
      return sanitizedObj;
    }
    return val;
  }

  /**
   * Validates, sanitizes, and saves a manifest payload.
   */
  public async processManifest(payload: any): Promise<IManifest> {
    if (!payload || !payload.creator || !payload.creatorId || !payload.contentHash || !payload.timestamp) {
      throw new Error('Validation Error: "contentHash", "creator", "creatorId", and "timestamp" are strictly required.');
    }

    const sanitizedMetadata = this.sanitizePayload(payload.metadata || {});

    const newManifest = new ManifestModel({
      contentHash: payload.contentHash,
      creator: payload.creator,
      creatorId: payload.creatorId,
      timestamp: new Date(payload.timestamp),
      metadata: sanitizedMetadata,
    });

    return await newManifest.save();
  }
}

export const manifestService = new ManifestService();