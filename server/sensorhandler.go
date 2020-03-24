// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "errors"
  "net/http"
  "github.com/sensoroni/sensoroni/model"
  "github.com/sensoroni/sensoroni/web"
)

type SensorHandler struct {
  web.BaseHandler
  server 		*Server
}

func NewSensorHandler(srv *Server) *SensorHandler {
  handler := &SensorHandler {}
  handler.Host = srv.Host
  handler.server = srv
  handler.Impl = handler
  return handler
}

func (sensorHandler *SensorHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  switch request.Method {
    case http.MethodPost: return sensorHandler.post(writer, request)
  }
  return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (sensorHandler *SensorHandler) post(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
  var job *model.Job
  sensor := model.NewSensor("")
  err := sensorHandler.ReadJson(request, sensor)
  if err == nil {
    err = sensorHandler.server.Datastore.UpdateSensor(sensor)
    if err == nil {
      sensorHandler.Host.Broadcast("sensor", sensor)
      job = sensorHandler.server.Datastore.GetNextJob(sensor.Id)
    }
  }
  return http.StatusOK, job, err
}