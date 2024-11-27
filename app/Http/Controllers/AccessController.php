<?php

namespace App\Http\Controllers;

use App\Models\Access;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;


class AccessController extends Controller
{
    public function index()
    {
        try {
            //Se usa la funcion select() del model Access para almacenar todos los datos de la tabla Access en la variable $access, despues se retorna una respuesta JSON que contiene el estado de la respuesta, lo ya almacenado en $access y el codigo http 200
            $access = Access::select();
            return response()->json([
                'status' => true,
                'data' => $access
            ],200);
        } catch (\Throwable $th) {
            //En caso de haber ocurrido algun error este será tratado por el try & catch y devolvera el error correspodiente con estado false y el codigo http 500
            return response()->json([
                'status' => false,
                'message' => $th
            ],500);
        }
    }
    public function store(Request $request)
    {
        //Se crea un arreglo con las reglas de validacion para cada campo de la tabla Acces
        $rules = [
            'proj_id' =>'required|integer|exists:projects',
            'use_id' =>'required|integer|exists:users'
        ];
        //Se usa la funcion make() del paquete Validator para validar los datos ingresados por el usuario
        $validator = Validator::make($request->input(), $rules);
        // se valida si alguna de las reglas falla al ser validada con los datos en el objeto request
        if ($validator->fails()) {
        //En caso de haber ocurrido algun error este devolverá el error correspodiente con estado false y el codigo http 500
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        }else{
            //Se usa el paquete DB para hacer una consulta en la tabla Access en la cual el proj_id dentro de la variable request del parametro, sea igual a los valores de la columna proj_id de la tabla, lo mismo se hace con la columna use_id. Se trae el primer valor encontrado usando la funcion first() y se almacena en la varibale $acces
            $acces = DB::table("access")->where('proj_id','=', $request->proj_id)->where('use_id','=', $request->use_id)->first();


            //Se usa un if para validar si el usuario ya pertenece al proyecto deseado, devolverá un mensaje de error en caso de que la variable $acces no esté vacia, de esta forma no habran datos repetidos.
            if ($acces != []) {
                return response()->json([
                    'status' => False,
                    'message' =>"This user already has access to this project"
                ]);
            }
            //En caso de que el usuario no pertenezca al proyecto deseado, se crea un nuevo registro en la tabla Access con los datos ingresados por el usuario
            $access = new Access($request->input());
            $access->acc_status = 1;
            $access->save();
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Access: $request->acc_id",3,$request->createdBy);
            return response()->json([
                'status' => True,
                'message' => "The access: ".$access->use_id." has been created."
            ],200);
        }
    }
    public function show($id)
    {
        //se usa la funcion search() del modelo Access para buscar un acceso en espicifico
        $access = Access::search($id);
        //Se usa un if para validar si el acceso buscado existe, devolverá un mensaje de error en caso de que la variable $access este vacia
        if ($access == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The searched access was not found']
            ],400);
        }else{
            return response()->json([
                'status' => true,
                'data' => $access
            ]);
        }
    }

        public function update(Request $request,$id)
    {
        //se usa la funcion find() del modelo Access para buscar un acceso en espicifico
        $acces = Access::find($id);
        $msg = $acces->acc_id;
        //Se usa un if para validar si el acceso buscado existe, devolverá un mensaje de error en caso de que la variable $acces este vacia
        if($acces == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The searched access was not found']
            ],400);
        }else{
            //Se crea un arreglo con las reglas de validacion para cada campo de la tabla Access
            $rules = [
                'proj_id' =>'required|integer|exists:projects',
                'use_id' =>'required|integer|exists:users',
            ];
            //Se usa la funcion make() del paquete Validator para validar los datos ingresados por el usuario
            $validator = Validator::make($request->input(), $rules);
            // se valida si alguna de las reglas falla al ser validada con los datos en el objeto request
            if ($validator->fails()) {
                return response()->json([
                    'status' => False,
                    'message' => $validator->errors()->all()
                ]);
            }else{
                //Se usa el paquete DB para hacer una consulta en la tabla Access en la cual el proj_id dentro de la variable request del parametro, sea igual a los valores de la columna proj_id de la tabla, lo mismo se hace con la columna use_id. Se trae el primer valor encontrado usando la funcion first() y se almacena en la variable $acces
                $access = DB::table("access")->where('proj_id','=', $request->proj_id)->where('use_id','=', $request->use_id)->first();
                //Se usa un if para validar si el usuario ya pertenece al proyecto deseado, devolverá un mensaje de error en caso de que la variable $acces no esté vacia
                if ($access != []) {
                    return response()->json([
                        'status' => False,
                        'message' =>"This user already has access to this project"
                    ]);
                }
                //En caso de que el usuario no pertenezca al proyecto deseado, se crea un nuevo registro en la tabla Access con los datos ingresados por el usuario
                $acces->acc_status = $request->acc_status;
                $acces->proj_id = $request->proj_id;
                $acces->use_id = $request->use_id;
                $acces->save();
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla Access del dato: id->$msg",1,$request->use_id);
                return response()->json([
                    'status' => True,
                    'message' => "The access: ".$acces->use_id." has been updated."
                ],200);
            }
        }
    }
    public function destroy($id, Request $request)
    {
        //se usa la funcion find() del modelo Access para buscar un acceso en espicifico
        $access = Access::find($id);
        //se valida el acc_status de la variable $access, si esta tiene un 1, se pasará a 0, de lo contrario se pasará a 1. Despues de esta validacion se guardará unicamente el acc_status
        $newStatus  = ($access->acc_status == 1) ? 0 : 1;
        $access->acc_status = $newStatus;
        $access->save();
        Controller::NewRegisterTrigger("Se le cambio el acceso al usuario:".$id.", por $newStatus ",2,$request->use_id);
        return response()->json([
            'status' => true,
            'message' => 'user status updated successfully'
        ]);
    }
}
