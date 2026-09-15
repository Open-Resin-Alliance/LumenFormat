import type {
    ComplexPluginDefinition,
    PluginLocalMaterialSettingsAdapterContract,
    MaterialSettingsSource,
} from '@/features/plugins/complexPluginContracts';
import { resolveDifferentialMaterialSettings } from '@/features/plugins/resolveDifferentialSettings';
import { LUMEN_PLUGIN_MANIFEST } from './pluginManifest';
import { LUMEN_FORMAT_DEFINITION } from './slicing/lumenFormatDefinition';
import lumenSimpleMaterialSettings from './materialSettings/settings_simple.json';
import lumenTwostageDiffMaterialSettings from './materialSettings/settings_twostage.diff.json';
import lumenAllFieldsDiffMaterialSettings from './materialSettings/settings_allfields.diff.json';
import lumenTiltingDiffMaterialSettings from './materialSettings/settings_tilting.diff.json';


function createLumenModeSettingsAdapter(
    modeName: string,
    allModeSources: Record<string, MaterialSettingsSource>,
): PluginLocalMaterialSettingsAdapterContract {
    const source = allModeSources[modeName];
    if (!source) {
        throw new Error(`[LUMEN] Settings mode "${modeName}" not found in mode sources`);
    }
    const resolved = resolveDifferentialMaterialSettings(source, allModeSources);
    return {
        outputFormat: LUMEN_FORMAT_DEFINITION.outputFormat,
        ...resolved,
    };
}

const LUMEN_MODE_SOURCES: Record<string, MaterialSettingsSource> = {
    simple: lumenSimpleMaterialSettings as MaterialSettingsSource,
    twostage: lumenTwostageDiffMaterialSettings as MaterialSettingsSource,
    allfields: lumenAllFieldsDiffMaterialSettings as MaterialSettingsSource,
    tilting: lumenTiltingDiffMaterialSettings as MaterialSettingsSource,
};

const LUMEN_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER = createLumenModeSettingsAdapter('simple', LUMEN_MODE_SOURCES);
const LUMEN_LOCAL_MATERIAL_SETTINGS_TWOSTAGE_ADAPTER = createLumenModeSettingsAdapter('twostage', LUMEN_MODE_SOURCES);
const LUMEN_LOCAL_MATERIAL_SETTINGS_ALLFIELDS_ADAPTER = createLumenModeSettingsAdapter('allfields', LUMEN_MODE_SOURCES);
const LUMEN_LOCAL_MATERIAL_SETTINGS_TILTING_ADAPTER = createLumenModeSettingsAdapter('tilting', LUMEN_MODE_SOURCES);

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
        [LUMEN_FORMAT_DEFINITION.outputFormat]: LUMEN_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER,
    },
    localMaterialSettingsByOutputAndMode: {
        [LUMEN_FORMAT_DEFINITION.outputFormat]: {
            simple: LUMEN_LOCAL_MATERIAL_SETTINGS_SIMPLE_ADAPTER,
            twostage: LUMEN_LOCAL_MATERIAL_SETTINGS_TWOSTAGE_ADAPTER,
            allfields: LUMEN_LOCAL_MATERIAL_SETTINGS_ALLFIELDS_ADAPTER,
            tilting: LUMEN_LOCAL_MATERIAL_SETTINGS_TILTING_ADAPTER,
        },
    },
};

export default LUMEN_COMPLEX_PLUGIN_DEFINITION;
