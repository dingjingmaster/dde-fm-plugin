//
// Created by dingjing on 2025/8/26.
//

#ifndef dde_fm_plugin_DDE_FM_PLUGIN_PLUGINS_H
#define dde_fm_plugin_DDE_FM_PLUGIN_PLUGINS_H

#include <list>
#include <string>
#include <dfm-extension/menu/dfmextmenuplugin.h>
#include <dfm-extension/emblemicon/dfmextemblemiconplugin.h>

class EmblemIconPlugins : public DFMEXT::DFMExtEmblemIconPlugin
{
public:
    EmblemIconPlugins();
    DFMEXT::DFMExtEmblem locationEmblemIcons(const std::string &filePath, int systemIconCount) const;

};

class MenuPlugins : public DFMEXT::DFMExtMenuPlugin
{
public:
    MenuPlugins();

    void initialize(DFMEXT::DFMExtMenuProxy *proxy) DFM_FAKE_OVERRIDE;
    bool buildNormalMenu(DFMEXT::DFMExtMenu *main,
                         const std::string &currentPath,
                         const std::string &focusPath,
                         const std::list<std::string> &pathList,
                         bool onDesktop) DFM_FAKE_OVERRIDE;

private:
    DFMEXT::DFMExtMenuProxy *mProxy { nullptr };

};

#endif // dde_fm_plugin_DDE_FM_PLUGIN_PLUGINS_H
