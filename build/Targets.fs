namespace ProjectBuild

module internal Targets =
    open System
    open System.IO

    open Fake.Core
    open Fake.DotNet
    open Fake.IO
    open Fake.IO.FileSystemOperators
    open Fake.IO.Globbing.Operators
    open Fake.Core.TargetOperators

    open Utils
    open Github.Types

    // --------------------------------------------------------------------------------------------------------
    // 2. Targets for FAKE
    // --------------------------------------------------------------------------------------------------------

    [<RequireQualifiedAccess>]
    module SafeStackTargets =
        open SafeBuildHelpers

        let init safe =
            Target.create "SafeClean" (fun _ ->
                Shell.cleanDir safe.DeployPath
                run dotnet "fable clean --yes" safe.ClientPath // Delete *.fs.js files created by Fable
            )

            Target.create "InstallClient" (fun _ ->
                run npm "--version" "."
                run npm "install" "."
            )

            Target.create "Bundle" (fun _ ->
                [
                    "server", dotnet $"publish -c Release -o \"{safe.DeployPath}\"" safe.ServerPath
                    "client", dotnet "fable -o output -s --run npm run build" safe.ClientPath
                ]
                |> runParallel
            )

            Target.create "Run" (fun _ ->
                run dotnet "build" safe.SharedPath
                [
                    "server", dotnet "watch run" safe.ServerPath
                    "client", dotnet "fable watch -o output -s --run npm run start" safe.ClientPath
                ]
                |> runParallel
            )

            Target.create "WatchTests" (fun _ ->
                run dotnet "build" safe.SharedTestsPath
                [
                    "server", dotnet "watch run" safe.ServerTestsPath
                    "client", dotnet "fable watch -o output -s --run npm run test:live" safe.ClientTestsPath
                ]
                |> runParallel
            )

            Target.create "Tests" (fun _ ->
                run dotnet "build" safe.SharedTestsPath
                [
                    "server", dotnet "run" safe.ServerTestsPath
                    // "client", dotnet "fable watch -o output -s --run npm run test:live" clientTestsPath
                ]
                |> runParallel
            )

            [
                "SafeClean"
                    ==> "Clean"

                "SafeClean"
                    ==> "AssemblyInfo"
                    ==> "InstallClient"
                    ==> "Build"

                "Tests"
                    ==> "Bundle"

                "Build"
                    ==> "Lint"
                    ==> "Tests" <=> "WatchTests"

                "Build"
                    ==> "Run"
            ]

    let init (definition: ProjectDefinition) =
        Target.initEnvironment ()

        Target.create "Info" (fun _ ->
            let separator sign = Trace.traceFAKE "%s" (String.replicate 69 sign)

            Trace.traceHeader "Project info"
            Trace.tracefn "Project: %s" definition.Project.Name
            Trace.tracefn "Summary: %s" definition.Project.Summary
            Trace.tracefn "Type: %s" definition.Specs.Type

            separator "-"

            Trace.tracefn "Git.branch: %s" (definition.Project.Git |> Option.map (fun git -> git.Branch) |> Option.defaultValue "unknown")
            Trace.tracefn "Git.commit: %s" (definition.Project.Git |> Option.map (fun git -> git.Commit) |> Option.defaultValue "unknown")
            Trace.tracefn "Git.repository: %s" (definition.Project.Git |> Option.bind (fun git -> git.Repository) |> Option.defaultValue "unknown")

            separator "-"

            Trace.tracefn "BuildNumber: %s" ("BUILD_NUMBER" |> envVar |> Option.defaultValue "-")

            match definition with
            | { Specs = SAFEStackApplication { TemplateVersion = templateVersion } } ->
                Trace.tracefn "SafeTemplateVersion: %s" templateVersion
            | _ -> ()

            separator "="
        )

        Target.create "Clean" <| skipOn "no-clean" (fun _ ->
            !! "./**/bin/Release"
            ++ "./**/bin/Debug"
            ++ "./**/obj"
            ++ "./**/.ionide"
            -- "./bin/console"
            -- "./build/**"
            |> Shell.cleanDirs
        )

        Target.create "AssemblyInfo" (fun _ ->
            let getAssemblyInfoAttributes projectName =
                let now = DateTime.Now

                let release =
                    definition.ChangeLog
                    |> Option.bind (fun changeLog ->
                        try ReleaseNotes.parse (System.IO.File.ReadAllLines changeLog |> Seq.filter ((<>) "## Unreleased")) |> Some
                        with _ -> None
                    )

                let gitValue fallbackEnvironmentVariableNames initialValue =
                    initialValue
                    |> String.replace "NoBranch" ""
                    |> stringToOption
                    |> Option.bindNone (fun _ -> fallbackEnvironmentVariableNames |> List.tryPick envVar)
                    |> Option.defaultValue "unknown"

                [
                    AssemblyInfo.Title projectName
                    AssemblyInfo.Product definition.Project.Name
                    AssemblyInfo.Description definition.Project.Summary

                    match release with
                    | Some release ->
                        AssemblyInfo.Version release.AssemblyVersion
                        AssemblyInfo.FileVersion release.AssemblyVersion
                    | _ ->
                        AssemblyInfo.Version "1.0"
                        AssemblyInfo.FileVersion "1.0"

                    AssemblyInfo.InternalsVisibleTo "tests"

                    match definition.Project.Git with
                    | None ->
                        AssemblyInfo.Metadata("gitbranch", null |> gitValue [ "GIT_BRANCH"; "branch" ])
                        AssemblyInfo.Metadata("gitcommit", null |> gitValue [ "GIT_COMMIT"; "commit" ])
                    | Some git ->
                        AssemblyInfo.Metadata("gitbranch", git.Branch |> gitValue [ "GIT_BRANCH"; "branch" ])
                        AssemblyInfo.Metadata("gitcommit", git.Commit |> gitValue [ "GIT_COMMIT"; "commit" ])

                    AssemblyInfo.Metadata("createdAt", now.ToString("yyyy-MM-dd HH:mm:ss"))
                    AssemblyInfo.Metadata("buildNumber", "BUILD_NUMBER" |> envVar |> Option.defaultValue "-")

                    match definition with
                    | { Specs = SAFEStackApplication { TemplateVersion = templateVersion } } ->
                        AssemblyInfo.Metadata("SafeTemplateVersion", templateVersion)
                    | _ -> ()
                ]

            let getProjectDetails (projectPath: string) =
                let projectName = IO.Path.GetFileNameWithoutExtension(projectPath)
                (
                    projectPath,
                    projectName,
                    IO.Path.GetDirectoryName(projectPath),
                    (getAssemblyInfoAttributes projectName)
                )

            definition.Sources.All
            |> Seq.map getProjectDetails
            |> Seq.iter (fun (_, _, folderName, attributes) ->
                AssemblyInfoFile.createFSharp (folderName </> "AssemblyInfo.fs") attributes
            )
        )

        Target.create "Build" (fun _ ->
            definition.Sources.All
            |> Seq.iter (Path.getDirectory >> Dotnet.runOrFail "build")
        )

        Target.create "Lint" <| skipOn "no-lint" (fun _ ->
            definition.Sources.All
            ++ "build/build.fsproj"
            |> Seq.iter (fun fsproj ->
                match Dotnet.runInRoot (sprintf "fsharplint lint %s" fsproj) with
                | Ok () -> Trace.tracefn "Lint %s is Ok" fsproj
                | Error e -> raise e
            )
        )

        if not definition.Specs.IsSAFEStack then
            Target.create "Tests" (fun _ ->
                if definition.Sources.Tests |> Seq.isEmpty
                then Trace.tracefn "There are no tests yet."
                else Dotnet.runOrFail "run" "tests"
            )

            let zipRelease releaseDir runtimeIds =
                if releaseDir </> "zipCompiled" |> File.exists
                then
                    let zipReleaseProcess = createProcess (releaseDir </> "zipCompiled")

                    Trace.tracefn "\nZipping released files in %s ..." releaseDir
                    run zipReleaseProcess "" "."
                    |> Trace.tracefn "Zip result:\n%A\n"

                Trace.tracefn "\nZip compiled files"
                runtimeIds
                |> List.iter (RuntimeId.value >> fun runtimeId ->
                    Trace.tracefn " -> zipping %s ..." runtimeId
                    let zipFile = sprintf "%s.zip" runtimeId
                    IO.File.Delete zipFile
                    Zip.zip releaseDir (releaseDir </> zipFile) !!(releaseDir </> runtimeId </> "*")
                )

            Target.create "Release" (fun _ ->
                match definition with
                | { Specs = Library { ReleaseDir = releaseDir; NugetApi = nugetApi } } ->
                    match "src" </> definition.Project.Name with
                    | releaseSource when releaseSource |> Directory.Exists ->
                        Dotnet.runOrFail "pack" releaseSource
                    | _ ->
                        Dotnet.runInRootOrFail "pack"

                    Directory.ensure releaseDir

                    !! "**/bin/**/*.nupkg"
                    |> Seq.iter (Shell.moveFile releaseDir)

                | { Specs = ConsoleApplication { RuntimeIds = runtimeIds; ReleaseSource = releaseSource; ReleaseDir = releaseDir } } ->
                    let releaseDir = Path.getFullName releaseDir

                    Trace.tracefn "\nClean previous releases"
                    runtimeIds
                    |> Seq.collect (RuntimeId.value >> fun runtimeId ->
                        Trace.tracefn " - %s" runtimeId
                        !! (releaseDir </> runtimeId)
                    )
                    |> Shell.cleanDirs

                    Trace.tracefn "\nClean previous zipped releases"
                    !! (releaseDir </> "*.zip")
                    ++ (releaseDir </> "*.tar.gz")
                    |> Seq.map (tee (Trace.tracefn " - %s"))
                    |> Seq.iter File.delete

                    Trace.tracefn "\nPublish current release"

                    seq {
                        let project = releaseSource
                        yield! runtimeIds |> List.collect (RuntimeId.value >> fun runtimeId -> [project, runtimeId])
                    }
                    |> Seq.iter (fun (project, runtimeId) ->
                        sprintf "publish -c Release /p:PublishSingleFile=true -o %s/%s --self-contained -r %s %s" releaseDir runtimeId runtimeId project
                        |> Dotnet.runInRootOrFail
                    )

                    runtimeIds |> zipRelease releaseDir

                | { Specs = Executable { ReleaseDir = releaseDir } } ->
                    releaseDir
                    |> sprintf "publish -c Release -o %s"
                    |> Dotnet.runInRootOrFail

                | { Specs = SAFEStackApplication _ } -> failwithf "For releasing SAFE-Stack Application, use \"bundle\" target instead."
            )

            Target.create "ZipRelease" (fun _ ->
                match definition with
                | { Specs = ConsoleApplication { RuntimeIds = runtimeIds; ReleaseDir = releaseDir } } ->
                    runtimeIds |> zipRelease releaseDir
                | _ -> ()
            )

            Target.create "Publish" (fun _ ->
                match definition with
                | { Specs = Library { NugetApi = NugetApi.NotUsed } } -> Trace.traceHeader "NugetApi is not used"

                | { Specs = Library { ReleaseDir = releaseDir; NugetApi = NugetApi.Organization organization; NugetCustomServerRepository = nugetServer } } ->
                    Trace.traceHeader "Pushing to organization nuget server"

                    envVar "PRIVATE_FEED_PASS"
                    |> Option.requireSome "Environment variable PRIVATE_FEED_PASS is not set."
                    |> Nuget.push releaseDir (Some organization)

                    match envVar "NUGET_SERVER_TOKEN", envVar "NUGET_SERVER_REPOSITORY" |> Option.orElse nugetServer with
                    | Some token, Some repository ->
                        Trace.tracefn "Trigger: Update %s readme" repository

                        Github.triggerAction {
                            EventType = "update-readme"
                            CurrentProject = definition.Project.Name
                            Token = token
                            Organization = envVar "NUGET_SERVER_ORGANIZATION" |> Option.defaultValue organization
                            Repository = repository
                        }
                        |> Async.RunSynchronously

                    | _ -> ()

                | { Specs = Library { ReleaseDir = releaseDir; NugetApi = NugetApi.AskForKey; Organization = organization }} ->
                    Trace.traceHeader "Pushing to public nuget server"

                    match UserInput.getUserInput "Are you sure - is it tagged yet? [y|n]: " with
                    | "y" | "yes" ->
                        match UserInput.getUserPassword "Nuget ApiKey: " with
                        | null | "" -> failwithf "You have to provide an api key for nuget."
                        | apiKey -> Nuget.push releaseDir organization apiKey
                    | _ -> ()

                | { Specs = Library { ReleaseDir = releaseDir; NugetApi = NugetApi.KeyInEnvironment name; Organization = organization }} ->
                    Trace.traceHeader "Pushing to nuget server"

                    envVar name
                    |> Option.iter (Nuget.push releaseDir organization)

                | _ -> ()
            )

            Target.create "Watch" (fun _ ->
                Dotnet.runInRootOrFail "watch run"
            )

            Target.create "Run" (fun _ ->
                Dotnet.runInRootOrFail "run"
            )

        // --------------------------------------------------------------------------------------------------------
        // 3. FAKE targets hierarchy
        // --------------------------------------------------------------------------------------------------------

        match definition with
        | { Specs = Library _ } ->
            [
                "Clean"
                    ==> "AssemblyInfo"
                    ==> "Build"
                    ==> "Lint"
                    ==> "Tests"
                    ==> "Release"
                    ==> "Publish"
            ]

        | { Specs = ConsoleApplication _ } ->
            [
                "Clean"
                    ==> "AssemblyInfo"
                    ==> "Build"
                    ==> "Lint"
                    ==> "Tests"
                    ==> "Release"
                    ==> "ZipRelease"

                "Build"
                    ==> "Watch" <=> "Run"
            ]

        | { Specs = Executable _ } ->
            [
                "Clean"
                    ==> "AssemblyInfo"
                    ==> "Build"
                    ==> "Lint"
                    ==> "Tests"
                    ==> "Release" <=> "Watch" <=> "Run"
            ]

        | { Specs = SAFEStackApplication safe } ->
            SafeStackTargets.init safe

        |> ignore
