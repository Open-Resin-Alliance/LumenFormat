import type {
    ComplexPluginDefinition,
    PluginLocalMaterialSettingsAdapterContract,
    MaterialSettingsSource,
} from '@/features/plugins/complexPluginContracts';
import { resolveDifferentialMaterialSettings } from '@/features/plugins/resolveDifferentialSettings';
import { LUMEN_PLUGIN_MANIFEST } from './pluginManifest';
import { LUMEN_FORMAT_DEFINITION } from './slicing/lumenFormatDefinition';
import lumenStandardMaterialSettings from './materialSettings/settings_standard.json';

/**
 * LUMEN's settings, filed under four tabs.
 *
 * General carries the everyday print settings. Motion carries the lift and the
 * retract in CTB's paired form: each first segment sits beside the second segment
 * of the same move, so a row shows both halves, the tags say which end is slow and
 * which is fast, and a single-stage machine reads the half it leaves at zero.
 * Advanced holds the burn-in waits, and the temperatures and the scene switch sit
 * on the profile's own Meta tab, which the app renders for any format that places
 * fields there.
 *
 * The format needs one mode: META always carries both the lift and the retract
 * segment, and the `lumen.*` namespace the encoder reads is already the
 * everything set, so a second mode would describe the same settings twice. A
 * tilting vat's motion belongs to the printer's firmware, and META's lift and
 * retract values stay required, so there is no tilting page either.
 *
 * The source still goes through the differential resolver the other formats use, so a
 * later mode can inherit these tabs by name.
 */
const LUMEN_STANDARD_SETTINGS = lumenStandardMaterialSettings as MaterialSettingsSource;

const LUMEN_MODE_SOURCES: Record<string, MaterialSettingsSource> = {
    standard: LUMEN_STANDARD_SETTINGS,
};

const LUMEN_LOCAL_MATERIAL_SETTINGS_STANDARD_ADAPTER: PluginLocalMaterialSettingsAdapterContract = {
    outputFormat: LUMEN_FORMAT_DEFINITION.outputFormat,
    ...resolveDifferentialMaterialSettings(LUMEN_STANDARD_SETTINGS, LUMEN_MODE_SOURCES),
};

export const LUMEN_COMPLEX_PLUGIN_DEFINITION: ComplexPluginDefinition = {
    id: 'lumen',
    manifest: LUMEN_PLUGIN_MANIFEST,
    capabilities: {
        networkOperations: false,
        uploadWithProgress: false,
        slicerEncoder: true,
        tauriRuntimePlugin: false,
    },
    slicingFormatsByOutput: {
        [LUMEN_FORMAT_DEFINITION.outputFormat]: LUMEN_FORMAT_DEFINITION,
    },
    localMaterialSettingsByOutput: {
        [LUMEN_FORMAT_DEFINITION.outputFormat]: LUMEN_LOCAL_MATERIAL_SETTINGS_STANDARD_ADAPTER,
    },
    localMaterialSettingsByOutputAndMode: {
        [LUMEN_FORMAT_DEFINITION.outputFormat]: {
            standard: LUMEN_LOCAL_MATERIAL_SETTINGS_STANDARD_ADAPTER,
        },
    },
    // `lumen.embedVoxlScene` asks for the editor scene; the host bakes it into the job
    // as VOXL V2 bytes and LUMEN's encoder copies it into a `VOXL` chunk.
    jobMetadataPayloads: [
        {
            settingPath: 'lumen.embedVoxlScene',
            payloadPath: 'lumen.voxlSceneBase64',
            payload: 'voxl-scene',
        },
    ],
};

export default LUMEN_COMPLEX_PLUGIN_DEFINITION;
