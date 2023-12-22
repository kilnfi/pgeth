package pgeth

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/mattn/go-colorable"
	"gopkg.in/yaml.v2"

	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/pgeth/toolkit"
	pgeth_monitoring "github.com/ethereum/go-ethereum/plugins/pgeth-monitoring"
)

type PluginDetails struct {
	Name   string                 `yaml:"name"`
	Config map[string]interface{} `yaml:"config"`
}

type Plugin struct {
	Details PluginDetails
	Start   func(*toolkit.PluginToolkit, map[string]interface{}, context.Context, chan (error))
	Version func()
}

type PluginEngineConfig struct {
	Node    *node.Node
	Backend ethapi.Backend
}

type PluginEngine struct {
	node    *node.Node
	backend ethapi.Backend
	logger  log.Logger
}

func NewEngine(cfg *PluginEngineConfig) *PluginEngine {
	logger := log.New()

	var ostream log.Handler
	output := colorable.NewColorableStdout()
	ostream = log.StreamHandler(output, log.PgethFormat(true))
	logger.SetHandler(ostream)
	return &PluginEngine{
		node:    cfg.Node,
		backend: cfg.Backend,
		logger:  logger,
	}
}

func (p *PluginEngine) Version(ctx context.Context) error {
	var plugins []*Plugin

	// load monitoring plugin
	if pluginConfigFile := os.Getenv("PGETH_MONITORING_CONFIG"); len(pluginConfigFile) != 0 {
		monitoringDetails, err := p.loadPluginDetails(pluginConfigFile)
		if err != nil {
			return err
		}
		plugins = append(plugins, &Plugin{
			Details: monitoringDetails,
			Version: pgeth_monitoring.Version,
			Start:   pgeth_monitoring.Start,
		})
	}

	for _, plug := range plugins {
		plug.Version()
	}

	errChan := make(chan error)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errChan:
				p.logger.Error(err.Error())
			}
		}
	}()

	return nil
}

func (p *PluginEngine) Start(ctx context.Context) error {
	var plugins []*Plugin

	// load monitoring plugin
	if pluginConfigFile := os.Getenv("PGETH_MONITORING_CONFIG"); len(pluginConfigFile) != 0 {
		monitoringDetails, err := p.loadPluginDetails(pluginConfigFile)
		if err != nil {
			return err
		}
		plugins = append(plugins, &Plugin{
			Details: monitoringDetails,
			Version: pgeth_monitoring.Version,
			Start:   pgeth_monitoring.Start,
		})
	}

	var toolkit = &toolkit.PluginToolkit{
		Node:    p.node,
		Backend: p.backend,
		Logger:  p.logger,
	}

	errChan := make(chan error)
	for _, plug := range plugins {
		go func(_plug *Plugin) {
			defer func() {
				if err := recover(); err != nil {
					p.logger.Error("Plugin crashed", "error", err, "plugin", _plug.Details.Name)
					// logs entire trace
					debug.PrintStack()
				}
			}()
			_plug.Start(toolkit, _plug.Details.Config, ctx, errChan)
		}(plug)
		p.logger.Info(fmt.Sprintf("Starting \"%s\" plugin", plug.Details.Name))
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errChan:
				p.logger.Error(err.Error())
			}
		}
	}()

	return nil
}

func (p *PluginEngine) loadPluginDetails(pluginConfigPath string) (PluginDetails, error) {
	var pluginDetails PluginDetails

	yamlFile, err := os.ReadFile(pluginConfigPath)
	if err != nil {
		return PluginDetails{}, err
	}
	err = yaml.Unmarshal(yamlFile, &pluginDetails)
	if err != nil {
		return PluginDetails{}, err
	}

	p.logger.Info(fmt.Sprintf("Loading config for \"%s\" = %+v", pluginDetails.Name, pluginDetails.Config))

	return pluginDetails, nil
}
