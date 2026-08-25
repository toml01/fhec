import "hardhat/types/config";

import type { FhecConfig, FhecUserConfig } from "./types";

declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    fhec?: FhecUserConfig;
  }

  interface HardhatConfig {
    fhec: FhecConfig;
  }
}
