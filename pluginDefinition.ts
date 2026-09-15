import type { ComplexPluginDefinition } from '@/features/plugins/complexPluginContracts';
import { LUMEN_PLUGIN_MANIFEST } from './pluginManifest';
import { LUMEN_FORMAT_DEFINITION } from './slicing/lumenFormatDefinition';

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
    localMaterialSettingsByOutput: {},
    localMaterialSettingsByOutputAndMode: {},
};

export default LUMEN_COMPLEX_PLUGIN_DEFINITION;
